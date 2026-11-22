//! Trato — pagamentos protegidos (escrow) e trocas OTC na Solana.
//!
//! Dois modos:
//! 1. Escrow de serviço/produto: o comprador deposita, o vendedor entrega,
//!    o dinheiro é liberado na confirmação (ou por prazo). Disputas são
//!    resolvidas por um árbitro, com saída automática se ele não agir.
//! 2. Troca OTC atômica: o maker deposita o token que oferece; qualquer
//!    pessoa (ou um taker específico) paga o valor pedido e recebe o token
//!    na mesma transação. Sem árbitro, sem disputa.
//!
//! Princípios de segurança:
//! - A pausa de emergência bloqueia apenas operações NOVAS. Reembolsos,
//!   cancelamentos, liberações e disputas sempre funcionam.
//! - As taxas têm teto gravado no código (MAX_FEE_BPS).
//! - Arredondamentos favorecem o usuário, nunca a tesouraria.
//! - Só dados mínimos ficam on-chain (os termos do acordo entram como hash).
//! - Tokens "doados" diretamente a um cofre nunca travam um negócio.
//! - MVP aceita apenas o padrão clássico de tokens (SPL Token), como USDC e
//!   USDT. O Token-2022 fica de fora por segurança: extensões como
//!   "permanent delegate" permitiriam ao emissor retirar tokens de qualquer
//!   conta, abrindo espaço para golpes na troca OTC.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, CloseAccount, Mint, Token, TokenAccount, TransferChecked};

declare_id!("7GGLHC2T67tbCwgxQ2ZYXouehHA38UYzqsmgbJ9Ho4mS");

// ---------------------------------------------------------------------------
// Constantes
// ---------------------------------------------------------------------------

pub const BPS_DENOMINATOR: u64 = 10_000;
/// Teto absoluto da taxa de escrow e OTC: 2%.
pub const MAX_FEE_BPS: u16 = 200;
/// Teto absoluto da taxa de disputa: 5%.
pub const MAX_DISPUTE_FEE_BPS: u16 = 500;

pub const HOUR: i64 = 60 * 60;
pub const DAY: i64 = 24 * HOUR;
pub const MIN_WINDOW_SECS: i64 = HOUR;
pub const MAX_DELIVERY_WINDOW_SECS: i64 = 90 * DAY;
pub const MAX_REVIEW_WINDOW_SECS: i64 = 30 * DAY;
pub const MIN_OTC_DURATION_SECS: i64 = 5 * 60;
pub const MAX_OTC_DURATION_SECS: i64 = 90 * DAY;
/// Se o árbitro não resolver uma disputa nesse prazo, qualquer parte pode
/// encerrá-la com divisão 50/50 e sem taxas.
pub const STALE_DISPUTE_SECS: i64 = 30 * DAY;

pub const CONFIG_SEED: &[u8] = b"config";
pub const MINT_SEED: &[u8] = b"mint";
pub const DEAL_SEED: &[u8] = b"deal";
pub const VAULT_SEED: &[u8] = b"vault";
pub const OTC_SEED: &[u8] = b"otc";
pub const OTC_VAULT_SEED: &[u8] = b"otc_vault";
pub const REP_SEED: &[u8] = b"rep";

// ---------------------------------------------------------------------------
// Programa
// ---------------------------------------------------------------------------

#[program]
pub mod trato {
    use super::*;

    // ----------------------------- Administração -----------------------------

    /// Cria a configuração global. Só a autoridade de upgrade do programa
    /// pode chamar (evita que alguém inicialize antes de nós).
    pub fn initialize_config(ctx: Context<InitializeConfig>, params: ConfigParams) -> Result<()> {
        validate_fees(params.fee_bps, params.otc_fee_bps, params.dispute_fee_bps)?;
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.admin.key();
        config.arbiter = params.arbiter;
        config.treasury = params.treasury;
        config.fee_bps = params.fee_bps;
        config.otc_fee_bps = params.otc_fee_bps;
        config.dispute_fee_bps = params.dispute_fee_bps;
        config.paused = false;
        config.bump = ctx.bumps.config;
        emit!(ConfigUpdated {
            admin: config.admin,
            arbiter: config.arbiter,
            treasury: config.treasury,
            fee_bps: config.fee_bps,
            otc_fee_bps: config.otc_fee_bps,
            dispute_fee_bps: config.dispute_fee_bps,
        });
        Ok(())
    }

    /// Atualiza parâmetros (inclusive troca de admin). Use um multisig como admin.
    pub fn update_config(ctx: Context<AdminOnly>, params: UpdateConfigParams) -> Result<()> {
        validate_fees(params.fee_bps, params.otc_fee_bps, params.dispute_fee_bps)?;
        require_keys_neq!(params.admin, Pubkey::default(), TratoError::InvalidParameter);
        let config = &mut ctx.accounts.config;
        config.admin = params.admin;
        config.arbiter = params.arbiter;
        config.treasury = params.treasury;
        config.fee_bps = params.fee_bps;
        config.otc_fee_bps = params.otc_fee_bps;
        config.dispute_fee_bps = params.dispute_fee_bps;
        emit!(ConfigUpdated {
            admin: config.admin,
            arbiter: config.arbiter,
            treasury: config.treasury,
            fee_bps: config.fee_bps,
            otc_fee_bps: config.otc_fee_bps,
            dispute_fee_bps: config.dispute_fee_bps,
        });
        Ok(())
    }

    /// Pausa de emergência: bloqueia criação/pagamento de negócios novos.
    pub fn set_paused(ctx: Context<AdminOnly>, paused: bool) -> Result<()> {
        ctx.accounts.config.paused = paused;
        emit!(PauseChanged { paused });
        Ok(())
    }

    /// Aprova (ou ajusta/desativa) uma moeda de pagamento, ex.: USDC, USDT.
    /// Valores em unidades mínimas do token (USDC: 1_000_000 = US$ 1).
    pub fn upsert_mint(ctx: Context<UpsertMint>, params: MintParams) -> Result<()> {
        require!(params.min_amount > 0, TratoError::InvalidParameter);
        require!(params.max_amount >= params.min_amount, TratoError::InvalidParameter);
        // Garante que a taxa mínima nunca consome o valor inteiro.
        require!(params.min_fee < params.min_amount, TratoError::InvalidParameter);
        require!(params.dispute_min_fee < params.min_amount, TratoError::InvalidParameter);

        let allowed = &mut ctx.accounts.allowed_mint;
        allowed.mint = ctx.accounts.mint.key();
        allowed.decimals = ctx.accounts.mint.decimals;
        allowed.min_amount = params.min_amount;
        allowed.max_amount = params.max_amount;
        allowed.min_fee = params.min_fee;
        allowed.dispute_min_fee = params.dispute_min_fee;
        allowed.enabled = params.enabled;
        allowed.bump = ctx.bumps.allowed_mint;
        emit!(MintUpdated {
            mint: allowed.mint,
            min_amount: allowed.min_amount,
            max_amount: allowed.max_amount,
            min_fee: allowed.min_fee,
            enabled: allowed.enabled,
        });
        Ok(())
    }

    // ----------------------------- Escrow de serviço -----------------------------

    /// O vendedor cria a cobrança. `buyer = None` gera um link aberto
    /// (quem pagar primeiro vira o comprador).
    #[allow(clippy::too_many_arguments)]
    pub fn create_deal(
        ctx: Context<CreateDeal>,
        deal_id: u64,
        buyer: Option<Pubkey>,
        amount: u64,
        fee_mode: FeeMode,
        terms_hash: [u8; 32],
        delivery_window: i64,
        review_window: i64,
    ) -> Result<()> {
        let config = &ctx.accounts.config;
        let allowed = &ctx.accounts.allowed_mint;
        require!(!config.paused, TratoError::Paused);
        require!(allowed.enabled, TratoError::MintNotAllowed);
        require!(
            amount >= allowed.min_amount && amount <= allowed.max_amount,
            TratoError::AmountOutOfRange
        );
        require!(
            (MIN_WINDOW_SECS..=MAX_DELIVERY_WINDOW_SECS).contains(&delivery_window),
            TratoError::InvalidWindow
        );
        require!(
            (MIN_WINDOW_SECS..=MAX_REVIEW_WINDOW_SECS).contains(&review_window),
            TratoError::InvalidWindow
        );
        let seller = ctx.accounts.seller.key();
        let buyer_key = buyer.unwrap_or_default();
        require_keys_neq!(buyer_key, seller, TratoError::SameParty);

        let fee = compute_fee(amount, config.fee_bps, allowed.min_fee)?;
        let buyer_fee = match fee_mode {
            FeeMode::Seller => 0,
            FeeMode::Buyer => fee,
            FeeMode::Split => fee / 2, // vendedor paga a metade arredondada para cima
        };
        let now = Clock::get()?.unix_timestamp;

        let deal = &mut ctx.accounts.deal;
        deal.seller = seller;
        deal.buyer = buyer_key;
        deal.mint = ctx.accounts.mint.key();
        deal.deal_id = deal_id;
        deal.amount = amount;
        deal.fee = fee;
        deal.buyer_fee = buyer_fee;
        deal.fee_mode = fee_mode;
        deal.terms_hash = terms_hash;
        deal.delivery_window = delivery_window;
        deal.review_window = review_window;
        deal.created_at = now;
        deal.funded_at = 0;
        deal.delivered_at = 0;
        deal.disputed_at = 0;
        deal.state = DealState::Created;
        deal.bump = ctx.bumps.deal;
        deal.vault_bump = ctx.bumps.vault;

        touch_reputation(&mut ctx.accounts.seller_rep, seller, ctx.bumps.seller_rep, now);

        emit!(DealCreated {
            deal: deal.key(),
            seller,
            buyer: buyer_key,
            mint: deal.mint,
            amount,
            fee,
            buyer_fee,
            terms_hash,
        });
        Ok(())
    }

    /// O comprador deposita o valor (+ a parte dele da taxa) no cofre.
    pub fn fund_deal(ctx: Context<FundDeal>) -> Result<()> {
        require!(!ctx.accounts.config.paused, TratoError::Paused);
        let buyer = ctx.accounts.buyer.key();
        let deal = &ctx.accounts.deal;
        require!(deal.state == DealState::Created, TratoError::InvalidState);
        require_keys_neq!(buyer, deal.seller, TratoError::SameParty);
        if deal.buyer != Pubkey::default() {
            require_keys_eq!(buyer, deal.buyer, TratoError::Unauthorized);
        }
        let deposit = deal.deposit()?;
        // Saldo antes do depósito: alguém pode ter "doado" tokens ao cofre.
        // Comparamos a diferença, nunca o saldo absoluto, para que doações
        // não consigam travar o negócio.
        let before = ctx.accounts.vault.amount;

        token::transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferChecked {
                    from: ctx.accounts.buyer_token_account.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                    authority: ctx.accounts.buyer.to_account_info(),
                },
            ),
            deposit,
            ctx.accounts.mint.decimals,
        )?;
        ctx.accounts.vault.reload()?;
        let received = ctx.accounts.vault.amount.checked_sub(before).ok_or(TratoError::MathOverflow)?;
        require!(received == deposit, TratoError::UnexpectedVaultBalance);

        let now = Clock::get()?.unix_timestamp;
        let deal = &mut ctx.accounts.deal;
        deal.buyer = buyer;
        deal.funded_at = now;
        deal.state = DealState::Funded;

        touch_reputation(&mut ctx.accounts.buyer_rep, buyer, ctx.bumps.buyer_rep, now);

        emit!(DealFunded { deal: deal.key(), buyer, deposit });
        Ok(())
    }

    /// O vendedor informa que entregou. Começa a contar o prazo de revisão.
    pub fn mark_delivered(ctx: Context<SellerAction>) -> Result<()> {
        let deal = &mut ctx.accounts.deal;
        require!(deal.state == DealState::Funded, TratoError::InvalidState);
        deal.delivered_at = Clock::get()?.unix_timestamp;
        deal.state = DealState::Delivered;
        emit!(DealDelivered { deal: deal.key() });
        Ok(())
    }

    /// O vendedor cancela uma cobrança que ainda não foi paga.
    pub fn cancel_deal(ctx: Context<CancelDeal>) -> Result<()> {
        require!(ctx.accounts.deal.state == DealState::Created, TratoError::InvalidState);
        let deal = &ctx.accounts.deal;
        let deal_id_bytes = deal.deal_id.to_le_bytes();
        let seeds: &[&[u8]] = &[DEAL_SEED, deal.seller.as_ref(), &deal_id_bytes, &[deal.bump]];
        // Tokens "doados" ao cofre vão para o vendedor, senão o cofre não fecharia.
        let leftover = ctx.accounts.vault.amount;
        if leftover > 0 {
            token::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.key(),
                    TransferChecked {
                        from: ctx.accounts.vault.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        to: ctx.accounts.seller_token_account.to_account_info(),
                        authority: ctx.accounts.deal.to_account_info(),
                    },
                    &[seeds],
                ),
                leftover,
                ctx.accounts.mint.decimals,
            )?;
        }
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            CloseAccount {
                account: ctx.accounts.vault.to_account_info(),
                destination: ctx.accounts.seller.to_account_info(),
                authority: ctx.accounts.deal.to_account_info(),
            },
            &[seeds],
        ))?;
        emit!(DealClosed { deal: deal.key(), outcome: DealOutcome::Cancelled, to_seller: 0, to_buyer: 0, to_treasury: 0 });
        Ok(())
    }

    /// O comprador confirma e libera o pagamento. Também vale para
    /// encerrar uma disputa a favor do vendedor (comprador cede).
    pub fn release(ctx: Context<SettleDeal>) -> Result<()> {
        let deal = &ctx.accounts.deal;
        require_keys_eq!(ctx.accounts.authority.key(), deal.buyer, TratoError::Unauthorized);
        require!(
            matches!(deal.state, DealState::Funded | DealState::Delivered | DealState::Disputed),
            TratoError::InvalidState
        );
        ctx.accounts.settle_release(DealOutcome::Released)
    }

    /// O vendedor recebe automaticamente se o comprador não reclamar
    /// dentro do prazo de revisão após a entrega.
    pub fn claim_after_review(ctx: Context<SettleDeal>) -> Result<()> {
        let deal = &ctx.accounts.deal;
        require_keys_eq!(ctx.accounts.authority.key(), deal.seller, TratoError::Unauthorized);
        require!(deal.state == DealState::Delivered, TratoError::InvalidState);
        let now = Clock::get()?.unix_timestamp;
        require!(
            now >= deal.delivered_at.saturating_add(deal.review_window),
            TratoError::TooEarly
        );
        ctx.accounts.settle_release(DealOutcome::ClaimedAfterReview)
    }

    /// O comprador recebe tudo de volta se o vendedor não entregar no prazo.
    pub fn refund_after_deadline(ctx: Context<SettleDeal>) -> Result<()> {
        let deal = &ctx.accounts.deal;
        require_keys_eq!(ctx.accounts.authority.key(), deal.buyer, TratoError::Unauthorized);
        require!(deal.state == DealState::Funded, TratoError::InvalidState);
        let now = Clock::get()?.unix_timestamp;
        require!(
            now >= deal.funded_at.saturating_add(deal.delivery_window),
            TratoError::TooEarly
        );
        ctx.accounts.settle_full_refund(DealOutcome::RefundedAfterDeadline)
    }

    /// O vendedor devolve tudo ao comprador (inclusive cedendo uma disputa). Sem taxas.
    pub fn seller_refund(ctx: Context<SettleDeal>) -> Result<()> {
        let deal = &ctx.accounts.deal;
        require_keys_eq!(ctx.accounts.authority.key(), deal.seller, TratoError::Unauthorized);
        require!(
            matches!(deal.state, DealState::Funded | DealState::Delivered | DealState::Disputed),
            TratoError::InvalidState
        );
        ctx.accounts.settle_full_refund(DealOutcome::RefundedBySeller)
    }

    /// Comprador ou vendedor abre uma disputa. O comprador só pode abrir
    /// antes de acabar o prazo de revisão.
    pub fn open_dispute(ctx: Context<OpenDispute>) -> Result<()> {
        let who = ctx.accounts.authority.key();
        let deal = &mut ctx.accounts.deal;
        require!(who == deal.buyer || who == deal.seller, TratoError::Unauthorized);
        let now = Clock::get()?.unix_timestamp;
        match deal.state {
            DealState::Funded => {}
            DealState::Delivered => require!(
                now < deal.delivered_at.saturating_add(deal.review_window),
                TratoError::TooLate
            ),
            _ => return err!(TratoError::InvalidState),
        }
        deal.state = DealState::Disputed;
        deal.disputed_at = now;
        emit!(DisputeOpened { deal: deal.key(), opened_by: who });
        Ok(())
    }

    /// O árbitro decide a divisão: `seller_bps` = parte do valor que vai ao
    /// vendedor (10_000 = tudo ao vendedor, 0 = tudo ao comprador).
    pub fn resolve_dispute(ctx: Context<SettleDeal>, seller_bps: u16) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.authority.key(),
            ctx.accounts.config.arbiter,
            TratoError::Unauthorized
        );
        require!(ctx.accounts.deal.state == DealState::Disputed, TratoError::InvalidState);
        require!(u64::from(seller_bps) <= BPS_DENOMINATOR, TratoError::InvalidParameter);
        ctx.accounts.settle_dispute(seller_bps)
    }

    /// Saída de segurança: se o árbitro não agir em 30 dias, qualquer parte
    /// encerra a disputa com 50/50 e sem nenhuma taxa.
    pub fn resolve_stale_dispute(ctx: Context<SettleDeal>) -> Result<()> {
        let who = ctx.accounts.authority.key();
        let deal = &ctx.accounts.deal;
        require!(who == deal.buyer || who == deal.seller, TratoError::Unauthorized);
        require!(deal.state == DealState::Disputed, TratoError::InvalidState);
        let now = Clock::get()?.unix_timestamp;
        require!(
            now >= deal.disputed_at.saturating_add(STALE_DISPUTE_SECS),
            TratoError::TooEarly
        );
        let deposit = deal.deposit()?;
        let to_seller = deal.amount / 2;
        let to_buyer = deposit.checked_sub(to_seller).ok_or(TratoError::MathOverflow)?;
        ctx.accounts.execute_payout(to_seller, to_buyer, 0)?;
        emit!(DealClosed {
            deal: ctx.accounts.deal.key(),
            outcome: DealOutcome::StaleDisputeSplit,
            to_seller,
            to_buyer,
            to_treasury: 0,
        });
        Ok(())
    }

    // ----------------------------- OTC atômico -----------------------------

    /// O maker deposita `offer_amount` do token oferecido e pede `ask_amount`
    /// do token desejado. Pelo menos um dos lados precisa ser uma moeda
    /// aprovada (ex.: USDC); a taxa é cobrada nesse lado.
    pub fn create_otc(
        ctx: Context<CreateOtc>,
        offer_id: u64,
        taker: Option<Pubkey>,
        offer_amount: u64,
        ask_amount: u64,
        duration: i64,
    ) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(!config.paused, TratoError::Paused);
        let offer_mint = ctx.accounts.offer_mint.key();
        let ask_mint = ctx.accounts.ask_mint.key();
        require_keys_neq!(offer_mint, ask_mint, TratoError::InvalidParameter);
        require!(offer_amount > 0 && ask_amount > 0, TratoError::InvalidParameter);
        require!(
            (MIN_OTC_DURATION_SECS..=MAX_OTC_DURATION_SECS).contains(&duration),
            TratoError::InvalidWindow
        );
        let maker = ctx.accounts.maker.key();
        let taker_key = taker.unwrap_or_default();
        require_keys_neq!(taker_key, maker, TratoError::SameParty);

        // Descobre qual lado é a moeda aprovada (preferência: o lado pedido).
        let (quote_side, quote_amount, allowed) =
            match (&ctx.accounts.ask_allowed, &ctx.accounts.offer_allowed) {
                (Some(a), _) if a.mint == ask_mint && a.enabled => (QuoteSide::Ask, ask_amount, a),
                (_, Some(o)) if o.mint == offer_mint && o.enabled => {
                    (QuoteSide::Offer, offer_amount, o)
                }
                _ => return err!(TratoError::NoQuoteMint),
            };
        require!(
            quote_amount >= allowed.min_amount && quote_amount <= allowed.max_amount,
            TratoError::AmountOutOfRange
        );
        let fee = compute_fee(quote_amount, config.otc_fee_bps, allowed.min_fee)?;

        token::transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferChecked {
                    from: ctx.accounts.maker_offer_token_account.to_account_info(),
                    mint: ctx.accounts.offer_mint.to_account_info(),
                    to: ctx.accounts.offer_vault.to_account_info(),
                    authority: ctx.accounts.maker.to_account_info(),
                },
            ),
            offer_amount,
            ctx.accounts.offer_mint.decimals,
        )?;
        ctx.accounts.offer_vault.reload()?;
        require!(
            ctx.accounts.offer_vault.amount == offer_amount,
            TratoError::UnexpectedVaultBalance
        );

        let now = Clock::get()?.unix_timestamp;
        let offer = &mut ctx.accounts.offer;
        offer.maker = maker;
        offer.taker = taker_key;
        offer.offer_mint = offer_mint;
        offer.offer_amount = offer_amount;
        offer.ask_mint = ask_mint;
        offer.ask_amount = ask_amount;
        offer.quote_side = quote_side;
        offer.fee = fee;
        offer.offer_id = offer_id;
        offer.created_at = now;
        offer.expires_at = now.checked_add(duration).ok_or(TratoError::MathOverflow)?;
        offer.bump = ctx.bumps.offer;
        offer.vault_bump = ctx.bumps.offer_vault;

        touch_reputation(&mut ctx.accounts.maker_rep, maker, ctx.bumps.maker_rep, now);

        emit!(OtcCreated {
            offer: offer.key(),
            maker,
            taker: taker_key,
            offer_mint,
            offer_amount,
            ask_mint,
            ask_amount,
            fee,
            expires_at: offer.expires_at,
        });
        Ok(())
    }

    /// O taker paga o valor pedido e recebe o token oferecido, na mesma transação.
    pub fn take_otc(ctx: Context<TakeOtc>) -> Result<()> {
        require!(!ctx.accounts.config.paused, TratoError::Paused);
        let taker = ctx.accounts.taker.key();
        let offer = &ctx.accounts.offer;
        require_keys_neq!(taker, offer.maker, TratoError::SameParty);
        if offer.taker != Pubkey::default() {
            require_keys_eq!(taker, offer.taker, TratoError::Unauthorized);
        }
        let now = Clock::get()?.unix_timestamp;
        require!(now < offer.expires_at, TratoError::Expired);

        let quote_mint = match offer.quote_side {
            QuoteSide::Ask => offer.ask_mint,
            QuoteSide::Offer => offer.offer_mint,
        };
        require_keys_eq!(
            ctx.accounts.treasury_token_account.mint,
            quote_mint,
            TratoError::InvalidTreasuryAccount
        );

        let (fee, offer_amount, ask_amount) = (offer.fee, offer.offer_amount, offer.ask_amount);
        let (to_taker, offer_fee, to_maker, ask_fee) = match offer.quote_side {
            QuoteSide::Ask => (
                offer_amount,
                0,
                ask_amount.checked_sub(fee).ok_or(TratoError::MathOverflow)?,
                fee,
            ),
            QuoteSide::Offer => (
                offer_amount.checked_sub(fee).ok_or(TratoError::MathOverflow)?,
                fee,
                ask_amount,
                0,
            ),
        };
        // Tokens "doados" ao cofre vão junto para o taker (o cofre precisa zerar para fechar).
        let excess = ctx
            .accounts
            .offer_vault
            .amount
            .checked_sub(offer_amount)
            .ok_or(TratoError::UnexpectedVaultBalance)?;
        let to_taker = to_taker.checked_add(excess).ok_or(TratoError::MathOverflow)?;

        let maker_key = offer.maker;
        let id_bytes = offer.offer_id.to_le_bytes();
        let bump = [offer.bump];
        let seeds: &[&[u8]] = &[OTC_SEED, maker_key.as_ref(), &id_bytes, &bump];
        let signer = &[seeds];

        let a = &ctx.accounts;
        // Taker -> maker (e taxa, se cobrada no lado pedido)
        token::transfer_checked(
            CpiContext::new(
                a.token_program.key(),
                TransferChecked {
                    from: a.taker_ask_token_account.to_account_info(),
                    mint: a.ask_mint.to_account_info(),
                    to: a.maker_ask_token_account.to_account_info(),
                    authority: a.taker.to_account_info(),
                },
            ),
            to_maker,
            a.ask_mint.decimals,
        )?;
        if ask_fee > 0 {
            token::transfer_checked(
                CpiContext::new(
                    a.token_program.key(),
                    TransferChecked {
                        from: a.taker_ask_token_account.to_account_info(),
                        mint: a.ask_mint.to_account_info(),
                        to: a.treasury_token_account.to_account_info(),
                        authority: a.taker.to_account_info(),
                    },
                ),
                ask_fee,
                a.ask_mint.decimals,
            )?;
        }
        // Cofre -> taker (e taxa, se cobrada no lado oferecido)
        token::transfer_checked(
            CpiContext::new_with_signer(
                a.token_program.key(),
                TransferChecked {
                    from: a.offer_vault.to_account_info(),
                    mint: a.offer_mint.to_account_info(),
                    to: a.taker_offer_token_account.to_account_info(),
                    authority: a.offer.to_account_info(),
                },
                signer,
            ),
            to_taker,
            a.offer_mint.decimals,
        )?;
        if offer_fee > 0 {
            token::transfer_checked(
                CpiContext::new_with_signer(
                    a.token_program.key(),
                    TransferChecked {
                        from: a.offer_vault.to_account_info(),
                        mint: a.offer_mint.to_account_info(),
                        to: a.treasury_token_account.to_account_info(),
                        authority: a.offer.to_account_info(),
                    },
                    signer,
                ),
                offer_fee,
                a.offer_mint.decimals,
            )?;
        }
        token::close_account(CpiContext::new_with_signer(
            a.token_program.key(),
            CloseAccount {
                account: a.offer_vault.to_account_info(),
                destination: a.maker.to_account_info(),
                authority: a.offer.to_account_info(),
            },
            signer,
        ))?;

        // Reputação: quem recebe menos é quem pagou a taxa.
        let quote_amount = match offer.quote_side {
            QuoteSide::Ask => ask_amount,
            QuoteSide::Offer => offer_amount,
        };
        let (maker_fee, taker_fee) = match offer.quote_side {
            QuoteSide::Ask => (fee, 0),
            QuoteSide::Offer => (0, fee),
        };
        let offer_key = ctx.accounts.offer.key();
        touch_reputation(&mut ctx.accounts.taker_rep, taker, ctx.bumps.taker_rep, now);
        record_otc(&mut ctx.accounts.taker_rep, quote_amount, taker_fee, now);
        record_otc(&mut ctx.accounts.maker_rep, quote_amount, maker_fee, now);

        emit!(OtcTaken { offer: offer_key, maker: maker_key, taker, fee });
        Ok(())
    }

    /// O maker cancela a oferta e recebe os tokens de volta (funciona mesmo pausado).
    pub fn cancel_otc(ctx: Context<CancelOtc>) -> Result<()> {
        let offer = &ctx.accounts.offer;
        let maker_key = offer.maker;
        let id_bytes = offer.offer_id.to_le_bytes();
        let bump = [offer.bump];
        let seeds: &[&[u8]] = &[OTC_SEED, maker_key.as_ref(), &id_bytes, &bump];
        let signer = &[seeds];
        let a = &ctx.accounts;
        let balance = a.offer_vault.amount;
        if balance > 0 {
            token::transfer_checked(
                CpiContext::new_with_signer(
                    a.token_program.key(),
                    TransferChecked {
                        from: a.offer_vault.to_account_info(),
                        mint: a.offer_mint.to_account_info(),
                        to: a.maker_offer_token_account.to_account_info(),
                        authority: a.offer.to_account_info(),
                    },
                    signer,
                ),
                balance,
                a.offer_mint.decimals,
            )?;
        }
        token::close_account(CpiContext::new_with_signer(
            a.token_program.key(),
            CloseAccount {
                account: a.offer_vault.to_account_info(),
                destination: a.maker.to_account_info(),
                authority: a.offer.to_account_info(),
            },
            signer,
        ))?;
        emit!(OtcCancelled { offer: ctx.accounts.offer.key() });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Lógica de taxas (funções puras, testáveis)
// ---------------------------------------------------------------------------

/// Taxa = max(valor * bps, mínimo), nunca maior que o valor.
pub fn compute_fee(amount: u64, bps: u16, min_fee: u64) -> Result<u64> {
    let pct = (amount as u128)
        .checked_mul(bps as u128)
        .ok_or(TratoError::MathOverflow)?
        / BPS_DENOMINATOR as u128;
    let pct = u64::try_from(pct).map_err(|_| TratoError::MathOverflow)?;
    Ok(pct.max(min_fee).min(amount))
}

/// Valor proporcional arredondado para baixo.
pub fn bps_of(value: u64, bps: u64) -> Result<u64> {
    let v = (value as u128)
        .checked_mul(bps as u128)
        .ok_or(TratoError::MathOverflow)?
        / BPS_DENOMINATOR as u128;
    u64::try_from(v).map_err(|_| error!(TratoError::MathOverflow))
}

/// Calcula a divisão de uma disputa. Retorna (vendedor, comprador, tesouraria).
/// A taxa de escrow incide só sobre a parte que vai ao vendedor; a taxa de
/// disputa sai da parte de quem perdeu (empate 50/50 = sem taxa de disputa).
/// Todas as frações de taxa são arredondadas para baixo (a favor do usuário).
pub fn dispute_split(
    amount: u64,
    fee: u64,
    buyer_fee: u64,
    seller_bps: u16,
    dispute_fee: u64,
) -> Result<(u64, u64, u64)> {
    let s = seller_bps as u64;
    let seller_fee = fee.checked_sub(buyer_fee).ok_or(TratoError::MathOverflow)?;
    let seller_gross = bps_of(amount, s)?;
    let buyer_gross = amount - seller_gross;
    let seller_fee_part = bps_of(seller_fee, s)?;
    let buyer_fee_part = bps_of(buyer_fee, s)?;

    let mut to_seller = seller_gross
        .checked_sub(seller_fee_part)
        .ok_or(TratoError::MathOverflow)?;
    let mut to_buyer = buyer_gross
        .checked_add(buyer_fee)
        .and_then(|v| v.checked_sub(buyer_fee_part))
        .ok_or(TratoError::MathOverflow)?;
    let mut to_treasury = seller_fee_part + buyer_fee_part;

    let half = BPS_DENOMINATOR / 2;
    if s > half {
        let d = dispute_fee.min(to_buyer);
        to_buyer -= d;
        to_treasury += d;
    } else if s < half {
        let d = dispute_fee.min(to_seller);
        to_seller -= d;
        to_treasury += d;
    }
    Ok((to_seller, to_buyer, to_treasury))
}

fn validate_fees(fee_bps: u16, otc_fee_bps: u16, dispute_fee_bps: u16) -> Result<()> {
    require!(fee_bps <= MAX_FEE_BPS, TratoError::FeeTooHigh);
    require!(otc_fee_bps <= MAX_FEE_BPS, TratoError::FeeTooHigh);
    require!(dispute_fee_bps <= MAX_DISPUTE_FEE_BPS, TratoError::FeeTooHigh);
    Ok(())
}

fn touch_reputation(rep: &mut Account<Reputation>, owner: Pubkey, bump: u8, now: i64) {
    if rep.owner == Pubkey::default() {
        rep.owner = owner;
        rep.bump = bump;
        rep.first_activity = now;
    }
    rep.last_activity = now;
}

fn record_otc(rep: &mut Account<Reputation>, volume: u64, fee_paid: u64, now: i64) {
    rep.otc_trades = rep.otc_trades.saturating_add(1);
    rep.volume = rep.volume.saturating_add(volume);
    rep.fees_paid = rep.fees_paid.saturating_add(fee_paid);
    rep.last_activity = now;
}

// ---------------------------------------------------------------------------
// Liquidação de negócios (compartilhada por várias instruções)
// ---------------------------------------------------------------------------

impl<'info> SettleDeal<'info> {
    /// Pagamento completo ao vendedor (liberação normal).
    fn settle_release(&mut self, outcome: DealOutcome) -> Result<()> {
        let deal = &self.deal;
        let seller_fee = deal.fee.checked_sub(deal.buyer_fee).ok_or(TratoError::MathOverflow)?;
        let to_seller = deal.amount.checked_sub(seller_fee).ok_or(TratoError::MathOverflow)?;
        let to_treasury = deal.fee;
        let (amount, fee, buyer_fee) = (deal.amount, deal.fee, deal.buyer_fee);
        self.execute_payout(to_seller, 0, to_treasury)?;

        let now = Clock::get()?.unix_timestamp;
        let s = &mut self.seller_rep;
        s.deals_as_seller = s.deals_as_seller.saturating_add(1);
        s.volume = s.volume.saturating_add(amount);
        s.fees_paid = s.fees_paid.saturating_add(fee - buyer_fee);
        s.last_activity = now;
        let b = &mut self.buyer_rep;
        b.deals_as_buyer = b.deals_as_buyer.saturating_add(1);
        b.volume = b.volume.saturating_add(amount);
        b.fees_paid = b.fees_paid.saturating_add(buyer_fee);
        b.last_activity = now;

        emit!(DealClosed { deal: self.deal.key(), outcome, to_seller, to_buyer: 0, to_treasury });
        Ok(())
    }

    /// Devolução integral ao comprador, sem taxa.
    fn settle_full_refund(&mut self, outcome: DealOutcome) -> Result<()> {
        let to_buyer = self.deal.deposit()?;
        self.execute_payout(0, to_buyer, 0)?;
        emit!(DealClosed { deal: self.deal.key(), outcome, to_seller: 0, to_buyer, to_treasury: 0 });
        Ok(())
    }

    fn settle_dispute(&mut self, seller_bps: u16) -> Result<()> {
        let deal = &self.deal;
        let dispute_fee = compute_fee(
            deal.amount,
            self.config.dispute_fee_bps,
            self.allowed_mint.dispute_min_fee,
        )?;
        let (to_seller, to_buyer, to_treasury) =
            dispute_split(deal.amount, deal.fee, deal.buyer_fee, seller_bps, dispute_fee)?;
        self.execute_payout(to_seller, to_buyer, to_treasury)?;

        let now = Clock::get()?.unix_timestamp;
        let half = (BPS_DENOMINATOR / 2) as u16;
        if seller_bps > half {
            self.seller_rep.disputes_won = self.seller_rep.disputes_won.saturating_add(1);
            self.buyer_rep.disputes_lost = self.buyer_rep.disputes_lost.saturating_add(1);
        } else if seller_bps < half {
            self.buyer_rep.disputes_won = self.buyer_rep.disputes_won.saturating_add(1);
            self.seller_rep.disputes_lost = self.seller_rep.disputes_lost.saturating_add(1);
        }
        self.seller_rep.last_activity = now;
        self.buyer_rep.last_activity = now;

        emit!(DealClosed {
            deal: self.deal.key(),
            outcome: DealOutcome::DisputeResolved,
            to_seller,
            to_buyer,
            to_treasury,
        });
        Ok(())
    }

    /// Faz as transferências a partir do cofre e fecha o cofre (aluguel volta
    /// ao vendedor, que pagou). A conta do negócio é fechada pelo `close = seller`.
    fn execute_payout(&self, to_seller: u64, to_buyer: u64, to_treasury: u64) -> Result<()> {
        let deal = &self.deal;
        let total = to_seller
            .checked_add(to_buyer)
            .and_then(|v| v.checked_add(to_treasury))
            .ok_or(TratoError::MathOverflow)?;
        // O cofre pode ter mais do que o esperado se alguém "doou" tokens a ele.
        // Nunca travamos por isso: a sobra vai para a tesouraria.
        require!(self.vault.amount >= total, TratoError::UnexpectedVaultBalance);
        let excess = self.vault.amount - total;
        let to_treasury = to_treasury.checked_add(excess).ok_or(TratoError::MathOverflow)?;

        let id_bytes = deal.deal_id.to_le_bytes();
        let bump = [deal.bump];
        let seeds: &[&[u8]] = &[DEAL_SEED, deal.seller.as_ref(), &id_bytes, &bump];
        let signer = &[seeds];

        for (dest, value) in [
            (self.seller_token_account.to_account_info(), to_seller),
            (self.buyer_token_account.to_account_info(), to_buyer),
            (self.treasury_token_account.to_account_info(), to_treasury),
        ] {
            if value == 0 {
                continue;
            }
            token::transfer_checked(
                CpiContext::new_with_signer(
                    self.token_program.key(),
                    TransferChecked {
                        from: self.vault.to_account_info(),
                        mint: self.mint.to_account_info(),
                        to: dest,
                        authority: self.deal.to_account_info(),
                    },
                    signer,
                ),
                value,
                self.mint.decimals,
            )?;
        }
        token::close_account(CpiContext::new_with_signer(
            self.token_program.key(),
            CloseAccount {
                account: self.vault.to_account_info(),
                destination: self.seller.to_account_info(),
                authority: self.deal.to_account_info(),
            },
            signer,
        ))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Contas (estado on-chain)
// ---------------------------------------------------------------------------

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    pub arbiter: Pubkey,
    /// Carteira dona das contas de token que recebem as taxas.
    pub treasury: Pubkey,
    pub fee_bps: u16,
    pub otc_fee_bps: u16,
    pub dispute_fee_bps: u16,
    pub paused: bool,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct AllowedMint {
    pub mint: Pubkey,
    pub decimals: u8,
    pub min_amount: u64,
    pub max_amount: u64,
    pub min_fee: u64,
    pub dispute_min_fee: u64,
    pub enabled: bool,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Deal {
    pub seller: Pubkey,
    /// Pubkey::default() enquanto o link estiver aberto e não pago.
    pub buyer: Pubkey,
    pub mint: Pubkey,
    pub deal_id: u64,
    pub amount: u64,
    /// Taxa total travada na criação.
    pub fee: u64,
    /// Parte da taxa paga pelo comprador (depositada junto com o valor).
    pub buyer_fee: u64,
    pub fee_mode: FeeMode,
    /// Hash (ex.: SHA-256) dos termos do acordo, guardados fora da blockchain.
    pub terms_hash: [u8; 32],
    pub delivery_window: i64,
    pub review_window: i64,
    pub created_at: i64,
    pub funded_at: i64,
    pub delivered_at: i64,
    pub disputed_at: i64,
    pub state: DealState,
    pub bump: u8,
    pub vault_bump: u8,
}

impl Deal {
    pub fn deposit(&self) -> Result<u64> {
        self.amount
            .checked_add(self.buyer_fee)
            .ok_or_else(|| error!(TratoError::MathOverflow))
    }
}

#[account]
#[derive(InitSpace)]
pub struct OtcOffer {
    pub maker: Pubkey,
    /// Pubkey::default() = qualquer pessoa pode aceitar.
    pub taker: Pubkey,
    pub offer_mint: Pubkey,
    pub offer_amount: u64,
    pub ask_mint: Pubkey,
    pub ask_amount: u64,
    pub quote_side: QuoteSide,
    pub fee: u64,
    pub offer_id: u64,
    pub created_at: i64,
    pub expires_at: i64,
    pub bump: u8,
    pub vault_bump: u8,
}

/// Histórico público de cada carteira. Base para pontos e reputação.
#[account]
#[derive(InitSpace)]
pub struct Reputation {
    pub owner: Pubkey,
    pub deals_as_seller: u32,
    pub deals_as_buyer: u32,
    pub otc_trades: u32,
    pub disputes_won: u32,
    pub disputes_lost: u32,
    /// Soma dos valores negociados (unidades mínimas das moedas aprovadas).
    pub volume: u64,
    /// Taxas efetivamente pagas — difícil de "farmar" sem custo real.
    pub fees_paid: u64,
    pub first_activity: i64,
    pub last_activity: i64,
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug, InitSpace)]
pub enum FeeMode {
    Seller,
    Buyer,
    Split,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug, InitSpace)]
pub enum DealState {
    Created,
    Funded,
    Delivered,
    Disputed,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug, InitSpace)]
pub enum QuoteSide {
    Offer,
    Ask,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum DealOutcome {
    Cancelled,
    Released,
    ClaimedAfterReview,
    RefundedAfterDeadline,
    RefundedBySeller,
    DisputeResolved,
    StaleDisputeSplit,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ConfigParams {
    pub arbiter: Pubkey,
    pub treasury: Pubkey,
    pub fee_bps: u16,
    pub otc_fee_bps: u16,
    pub dispute_fee_bps: u16,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct UpdateConfigParams {
    pub admin: Pubkey,
    pub arbiter: Pubkey,
    pub treasury: Pubkey,
    pub fee_bps: u16,
    pub otc_fee_bps: u16,
    pub dispute_fee_bps: u16,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct MintParams {
    pub min_amount: u64,
    pub max_amount: u64,
    pub min_fee: u64,
    pub dispute_min_fee: u64,
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Contextos (validação de contas)
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(
        init,
        payer = admin,
        space = 8 + Config::INIT_SPACE,
        seeds = [CONFIG_SEED],
        bump
    )]
    pub config: Account<'info, Config>,
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ TratoError::Unauthorized)]
    pub program: Program<'info, crate::program::Trato>,
    #[account(constraint = program_data.upgrade_authority_address == Some(admin.key()) @ TratoError::Unauthorized)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    pub admin: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ TratoError::Unauthorized)]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
pub struct UpsertMint<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ TratoError::Unauthorized)]
    pub config: Account<'info, Config>,
    pub mint: Account<'info, Mint>,
    #[account(
        init_if_needed,
        payer = admin,
        space = 8 + AllowedMint::INIT_SPACE,
        seeds = [MINT_SEED, mint.key().as_ref()],
        bump
    )]
    pub allowed_mint: Account<'info, AllowedMint>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(deal_id: u64)]
pub struct CreateDeal<'info> {
    #[account(mut)]
    pub seller: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    #[account(
        seeds = [MINT_SEED, mint.key().as_ref()],
        bump = allowed_mint.bump,
        constraint = allowed_mint.mint == mint.key() @ TratoError::MintNotAllowed
    )]
    pub allowed_mint: Box<Account<'info, AllowedMint>>,
    pub mint: Box<Account<'info, Mint>>,
    #[account(
        init,
        payer = seller,
        space = 8 + Deal::INIT_SPACE,
        seeds = [DEAL_SEED, seller.key().as_ref(), &deal_id.to_le_bytes()],
        bump
    )]
    pub deal: Box<Account<'info, Deal>>,
    #[account(
        init,
        payer = seller,
        seeds = [VAULT_SEED, deal.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = deal
    )]
    pub vault: Box<Account<'info, TokenAccount>>,
    #[account(
        init_if_needed,
        payer = seller,
        space = 8 + Reputation::INIT_SPACE,
        seeds = [REP_SEED, seller.key().as_ref()],
        bump
    )]
    pub seller_rep: Box<Account<'info, Reputation>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FundDeal<'info> {
    #[account(mut)]
    pub buyer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    #[account(
        mut,
        seeds = [DEAL_SEED, deal.seller.as_ref(), &deal.deal_id.to_le_bytes()],
        bump = deal.bump
    )]
    pub deal: Box<Account<'info, Deal>>,
    #[account(address = deal.mint)]
    pub mint: Box<Account<'info, Mint>>,
    #[account(
        mut,
        seeds = [VAULT_SEED, deal.key().as_ref()],
        bump = deal.vault_bump
    )]
    pub vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = mint,
        token::authority = buyer
    )]
    pub buyer_token_account: Box<Account<'info, TokenAccount>>,
    #[account(
        init_if_needed,
        payer = buyer,
        space = 8 + Reputation::INIT_SPACE,
        seeds = [REP_SEED, buyer.key().as_ref()],
        bump
    )]
    pub buyer_rep: Box<Account<'info, Reputation>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SellerAction<'info> {
    pub seller: Signer<'info>,
    #[account(
        mut,
        seeds = [DEAL_SEED, deal.seller.as_ref(), &deal.deal_id.to_le_bytes()],
        bump = deal.bump,
        has_one = seller @ TratoError::Unauthorized
    )]
    pub deal: Account<'info, Deal>,
}

#[derive(Accounts)]
pub struct CancelDeal<'info> {
    #[account(mut)]
    pub seller: Signer<'info>,
    #[account(
        mut,
        seeds = [DEAL_SEED, deal.seller.as_ref(), &deal.deal_id.to_le_bytes()],
        bump = deal.bump,
        has_one = seller @ TratoError::Unauthorized,
        close = seller
    )]
    pub deal: Box<Account<'info, Deal>>,
    #[account(
        mut,
        seeds = [VAULT_SEED, deal.key().as_ref()],
        bump = deal.vault_bump
    )]
    pub vault: Box<Account<'info, TokenAccount>>,
    #[account(address = deal.mint)]
    pub mint: Box<Account<'info, Mint>>,
    /// Recebe eventuais tokens "doados" ao cofre antes do cancelamento.
    #[account(mut, token::mint = mint, token::authority = seller)]
    pub seller_token_account: Box<Account<'info, TokenAccount>>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct OpenDispute<'info> {
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [DEAL_SEED, deal.seller.as_ref(), &deal.deal_id.to_le_bytes()],
        bump = deal.bump
    )]
    pub deal: Account<'info, Deal>,
}

/// Contas usadas por todas as formas de encerrar um negócio pago.
#[derive(Accounts)]
pub struct SettleDeal<'info> {
    /// Quem assina: comprador, vendedor ou árbitro (validado em cada instrução).
    pub authority: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    #[account(
        mut,
        seeds = [DEAL_SEED, deal.seller.as_ref(), &deal.deal_id.to_le_bytes()],
        bump = deal.bump,
        close = seller
    )]
    pub deal: Box<Account<'info, Deal>>,
    /// Recebe de volta o aluguel das contas (foi ele quem pagou).
    #[account(mut, address = deal.seller @ TratoError::Unauthorized)]
    pub seller: SystemAccount<'info>,
    #[account(seeds = [MINT_SEED, deal.mint.as_ref()], bump = allowed_mint.bump)]
    pub allowed_mint: Box<Account<'info, AllowedMint>>,
    #[account(address = deal.mint)]
    pub mint: Box<Account<'info, Mint>>,
    #[account(
        mut,
        seeds = [VAULT_SEED, deal.key().as_ref()],
        bump = deal.vault_bump
    )]
    pub vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = mint,
        token::authority = deal.seller
    )]
    pub seller_token_account: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = mint,
        token::authority = deal.buyer
    )]
    pub buyer_token_account: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = mint,
        token::authority = config.treasury
    )]
    pub treasury_token_account: Box<Account<'info, TokenAccount>>,
    #[account(mut, seeds = [REP_SEED, deal.seller.as_ref()], bump = seller_rep.bump)]
    pub seller_rep: Box<Account<'info, Reputation>>,
    #[account(mut, seeds = [REP_SEED, deal.buyer.as_ref()], bump = buyer_rep.bump)]
    pub buyer_rep: Box<Account<'info, Reputation>>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
#[instruction(offer_id: u64)]
pub struct CreateOtc<'info> {
    #[account(mut)]
    pub maker: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    pub offer_mint: Box<Account<'info, Mint>>,
    pub ask_mint: Box<Account<'info, Mint>>,
    /// Registro de moeda aprovada do token oferecido (opcional).
    pub offer_allowed: Option<Box<Account<'info, AllowedMint>>>,
    /// Registro de moeda aprovada do token pedido (opcional).
    pub ask_allowed: Option<Box<Account<'info, AllowedMint>>>,
    #[account(
        init,
        payer = maker,
        space = 8 + OtcOffer::INIT_SPACE,
        seeds = [OTC_SEED, maker.key().as_ref(), &offer_id.to_le_bytes()],
        bump
    )]
    pub offer: Box<Account<'info, OtcOffer>>,
    #[account(
        init,
        payer = maker,
        seeds = [OTC_VAULT_SEED, offer.key().as_ref()],
        bump,
        token::mint = offer_mint,
        token::authority = offer
    )]
    pub offer_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = offer_mint,
        token::authority = maker
    )]
    pub maker_offer_token_account: Box<Account<'info, TokenAccount>>,
    #[account(
        init_if_needed,
        payer = maker,
        space = 8 + Reputation::INIT_SPACE,
        seeds = [REP_SEED, maker.key().as_ref()],
        bump
    )]
    pub maker_rep: Box<Account<'info, Reputation>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TakeOtc<'info> {
    #[account(mut)]
    pub taker: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    #[account(
        mut,
        seeds = [OTC_SEED, offer.maker.as_ref(), &offer.offer_id.to_le_bytes()],
        bump = offer.bump,
        close = maker
    )]
    pub offer: Box<Account<'info, OtcOffer>>,
    #[account(mut, address = offer.maker @ TratoError::Unauthorized)]
    pub maker: SystemAccount<'info>,
    #[account(address = offer.offer_mint)]
    pub offer_mint: Box<Account<'info, Mint>>,
    #[account(address = offer.ask_mint)]
    pub ask_mint: Box<Account<'info, Mint>>,
    #[account(
        mut,
        seeds = [OTC_VAULT_SEED, offer.key().as_ref()],
        bump = offer.vault_bump
    )]
    pub offer_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = offer_mint,
        token::authority = taker
    )]
    pub taker_offer_token_account: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = ask_mint,
        token::authority = taker
    )]
    pub taker_ask_token_account: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = ask_mint,
        token::authority = offer.maker
    )]
    pub maker_ask_token_account: Box<Account<'info, TokenAccount>>,
    /// Conta da tesouraria na moeda em que a taxa é cobrada (validada na instrução).
    #[account(mut, token::authority = config.treasury)]
    pub treasury_token_account: Box<Account<'info, TokenAccount>>,
    #[account(
        init_if_needed,
        payer = taker,
        space = 8 + Reputation::INIT_SPACE,
        seeds = [REP_SEED, taker.key().as_ref()],
        bump
    )]
    pub taker_rep: Box<Account<'info, Reputation>>,
    #[account(mut, seeds = [REP_SEED, offer.maker.as_ref()], bump = maker_rep.bump)]
    pub maker_rep: Box<Account<'info, Reputation>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CancelOtc<'info> {
    #[account(mut)]
    pub maker: Signer<'info>,
    #[account(
        mut,
        seeds = [OTC_SEED, offer.maker.as_ref(), &offer.offer_id.to_le_bytes()],
        bump = offer.bump,
        has_one = maker @ TratoError::Unauthorized,
        close = maker
    )]
    pub offer: Box<Account<'info, OtcOffer>>,
    #[account(address = offer.offer_mint)]
    pub offer_mint: Box<Account<'info, Mint>>,
    #[account(
        mut,
        seeds = [OTC_VAULT_SEED, offer.key().as_ref()],
        bump = offer.vault_bump
    )]
    pub offer_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = offer_mint,
        token::authority = maker
    )]
    pub maker_offer_token_account: Box<Account<'info, TokenAccount>>,
    pub token_program: Program<'info, Token>,
}

// ---------------------------------------------------------------------------
// Eventos (para o site e para indexar o histórico)
// ---------------------------------------------------------------------------

#[event]
pub struct ConfigUpdated {
    pub admin: Pubkey,
    pub arbiter: Pubkey,
    pub treasury: Pubkey,
    pub fee_bps: u16,
    pub otc_fee_bps: u16,
    pub dispute_fee_bps: u16,
}

#[event]
pub struct PauseChanged {
    pub paused: bool,
}

#[event]
pub struct MintUpdated {
    pub mint: Pubkey,
    pub min_amount: u64,
    pub max_amount: u64,
    pub min_fee: u64,
    pub enabled: bool,
}

#[event]
pub struct DealCreated {
    pub deal: Pubkey,
    pub seller: Pubkey,
    pub buyer: Pubkey,
    pub mint: Pubkey,
    pub amount: u64,
    pub fee: u64,
    pub buyer_fee: u64,
    pub terms_hash: [u8; 32],
}

#[event]
pub struct DealFunded {
    pub deal: Pubkey,
    pub buyer: Pubkey,
    pub deposit: u64,
}

#[event]
pub struct DealDelivered {
    pub deal: Pubkey,
}

#[event]
pub struct DisputeOpened {
    pub deal: Pubkey,
    pub opened_by: Pubkey,
}

#[event]
pub struct DealClosed {
    pub deal: Pubkey,
    pub outcome: DealOutcome,
    pub to_seller: u64,
    pub to_buyer: u64,
    pub to_treasury: u64,
}

#[event]
pub struct OtcCreated {
    pub offer: Pubkey,
    pub maker: Pubkey,
    pub taker: Pubkey,
    pub offer_mint: Pubkey,
    pub offer_amount: u64,
    pub ask_mint: Pubkey,
    pub ask_amount: u64,
    pub fee: u64,
    pub expires_at: i64,
}

#[event]
pub struct OtcTaken {
    pub offer: Pubkey,
    pub maker: Pubkey,
    pub taker: Pubkey,
    pub fee: u64,
}

#[event]
pub struct OtcCancelled {
    pub offer: Pubkey,
}

// ---------------------------------------------------------------------------
// Erros
// ---------------------------------------------------------------------------

#[error_code]
pub enum TratoError {
    #[msg("O sistema está pausado para novas operações.")]
    Paused,
    #[msg("Você não tem permissão para esta ação.")]
    Unauthorized,
    #[msg("Esta ação não é permitida no estado atual do negócio.")]
    InvalidState,
    #[msg("Moeda não aprovada.")]
    MintNotAllowed,
    #[msg("Nenhum dos lados da troca é uma moeda aprovada.")]
    NoQuoteMint,
    #[msg("Valor fora dos limites permitidos.")]
    AmountOutOfRange,
    #[msg("Prazo inválido.")]
    InvalidWindow,
    #[msg("Comprador e vendedor precisam ser carteiras diferentes.")]
    SameParty,
    #[msg("Taxa acima do teto permitido.")]
    FeeTooHigh,
    #[msg("Parâmetro inválido.")]
    InvalidParameter,
    #[msg("Ainda não é possível: o prazo não terminou.")]
    TooEarly,
    #[msg("O prazo para esta ação já terminou.")]
    TooLate,
    #[msg("A oferta expirou.")]
    Expired,
    #[msg("Saldo do cofre diferente do esperado.")]
    UnexpectedVaultBalance,
    #[msg("Conta da tesouraria inválida para esta moeda.")]
    InvalidTreasuryAccount,
    #[msg("Erro de cálculo (overflow).")]
    MathOverflow,
}

// ---------------------------------------------------------------------------
// Testes das regras de taxa (rodam com `cargo test`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod fee_tests {
    use super::*;

    const USD: u64 = 1_000_000;

    #[test]
    fn fee_percent_min_and_cap() {
        // 1% de US$ 100 = US$ 1
        assert_eq!(compute_fee(100 * USD, 100, USD / 4).unwrap(), USD);
        // 1% de US$ 10 = 0,10 -> mínimo de 0,25
        assert_eq!(compute_fee(10 * USD, 100, USD / 4).unwrap(), USD / 4);
        // nunca maior que o valor
        assert_eq!(compute_fee(100, 100, 1_000).unwrap(), 100);
    }

    #[test]
    fn dispute_split_conserves_value() {
        let amount = 100 * USD + 7;
        let fee = compute_fee(amount, 100, USD / 4).unwrap();
        for buyer_fee in [0, fee / 2, fee] {
            for s in [0u16, 1, 2_500, 4_999, 5_000, 5_001, 7_333, 9_999, 10_000] {
                let (a, b, t) = dispute_split(amount, fee, buyer_fee, s, 5 * USD).unwrap();
                assert_eq!(a + b + t, amount + buyer_fee, "s={s} bf={buyer_fee}");
            }
        }
    }

    #[test]
    fn dispute_split_examples() {
        let amount = 100 * USD;
        let fee = USD; // 1%
        // Tudo ao vendedor, taxa paga pelo vendedor, comprador perde -> paga taxa de disputa
        let (s, b, t) = dispute_split(amount, fee, 0, 10_000, 5 * USD).unwrap();
        assert_eq!((s, b, t), (99 * USD, 0, USD));
        // Tudo ao comprador: vendedor perde, mas só tem 0 -> taxa de disputa limitada a 0
        let (s, b, t) = dispute_split(amount, fee, 0, 0, 5 * USD).unwrap();
        assert_eq!((s, b, t), (0, 100 * USD, 0));
        // 50/50, sem taxa de disputa; escrow cobra metade da taxa (só sobre a parte do vendedor)
        let (s, b, t) = dispute_split(amount, fee, 0, 5_000, 5 * USD).unwrap();
        assert_eq!((s, b, t), (50 * USD - USD / 2, 50 * USD, USD / 2));
        // 70% vendedor, comprador perde e paga a taxa de disputa
        let (s, b, t) = dispute_split(amount, fee, 0, 7_000, 5 * USD).unwrap();
        assert_eq!(s, 70 * USD - 7 * USD / 10);
        assert_eq!(b, 30 * USD - 5 * USD);
        assert_eq!(t, 7 * USD / 10 + 5 * USD);
    }
}
