use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::{components::*, *};

#[cfg(feature = "ssr")]
pub mod auth;
#[cfg(feature = "ssr")]
pub mod db;

//
// ───────────────────── Hydrate entrypoint (client) ─────────────────────
//

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}

//
// ─────────────────────────── App & Routes ───────────────────────────
//

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/manage_my_credit_card.css"/>
        <Title text="Leptos Auth Demo"/>

        <Router>
            <div class="app-root">
                <header class="app-header">
                    <a href="/" class="brand">
                        <span class="brand-logo">"LC"</span>
                        <span class="brand-text">
                            <span class="brand-title">"Leptos Auth"</span>
                            <span class="brand-subtitle">"Secure demo dashboard"</span>
                        </span>
                    </a>

                    <nav class="app-nav">
                        <a href="/login" class="nav-link">"Login"</a>
                        <a href="/register" class="nav-link nav-link--primary">"Register"</a>
                    </nav>
                </header>

                <main class="app-main">
                    <Routes fallback=|| "Page not found".into_view()>
                        <Route path=StaticSegment("") view=HomePage/>
                        <Route path=StaticSegment("login") view=LoginPage/>
                        <Route path=StaticSegment("register") view=RegisterPage/>
                        <Route path=StaticSegment("dashboard") view=DashboardPage/>
                    </Routes>
                </main>
            </div>
        </Router>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    view! {
        <div class="page page--center">
            <section class="hero">
                <div class="hero-copy">
                    <p class="eyebrow">"Manage My Credit Card"</p>
                    <h1>"Modern auth demo, built with Leptos & Axum"</h1>
                    <p class="hero-subtitle">
                        "Sign in to explore a minimal, production-style auth flow with a polished UI."
                    </p>

                    <div class="hero-actions">
                        <a href="/login" class="btn btn-primary">"Login"</a>
                        <a href="/register" class="btn btn-ghost">"Create account"</a>
                    </div>
                </div>

                <div class="hero-card glass-card">
                    <p class="hero-card-label">"Quick peek"</p>
                    <p class="hero-card-title">"JWT-secured dashboard"</p>
                    <p class="hero-card-body">
                        "Client-side token storage, protected API calls, and a clean starter layout."
                    </p>
                    <ul class="hero-list">
                        <li>"• Email / username + password auth"</li>
                        <li>"• Token-based dashboard access"</li>
                        <li>"• Error & loading states"</li>
                    </ul>
                </div>
            </section>
        </div>
    }
}

//
// ─────────────────────── Browser-side helpers ───────────────────────
//
#[cfg(feature = "ssr")]
async fn token_from_cookie() -> Result<String, ServerFnError> {
    use axum_extra::extract::cookie::CookieJar;
    use leptos_axum::extract;

    // Extract CookieJar from the current request (async)
    let jar: CookieJar = extract().await?;

    let cookie = jar
        .get("auth_token")
        .ok_or_else(|| ServerFnError::new("auth_token cookie not found".to_string()))?;

    Ok(cookie.value().to_string())
}

#[server(Logout, "/api")]
pub async fn logout_server() -> Result<(), ServerFnError> {
    #[cfg(feature = "ssr")]
    {
        use cookie::{Cookie, SameSite};
        use http::header;
        use leptos::prelude::*;
        use leptos_axum::ResponseOptions;

        let response = expect_context::<ResponseOptions>();

        // Set the cookie with empty value and Max-Age=0 to expire it
        let cookie = Cookie::build("auth_token") // name only, empty value
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(cookie::time::Duration::seconds(0))
            .build(); // use build(), not finish();

        if let Ok(value) = http::HeaderValue::from_str(&cookie.to_string()) {
            response.insert_header(header::SET_COOKIE, value);
        } else {
            log::error!("Failed to convert logout cookie to HeaderValue");
            return Err(ServerFnError::new("Internal error clearing cookie"));
        }
    }

    Ok(())
}

//
// ───────────────────────── Login / Register ─────────────────────────
//

#[component]
fn LoginPage() -> impl IntoView {
    let (username, set_username) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (error, set_error) = signal(None::<String>);
    let (loading, set_loading) = signal(false);

    let on_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        #[cfg(not(feature = "ssr"))]
        leptos::logging::log!("Login form submitted for: {}", username.get());

        set_loading.set(true);
        set_error.set(None);

        let username_val = username.get();
        let password_val = password.get();

        leptos::task::spawn_local(async move {
            let result = login(username_val.clone(), password_val.clone()).await;

            #[cfg(not(feature = "ssr"))]
            leptos::logging::log!("Login result: {:?}", result.is_ok());

            match result {
                Ok(()) => {
                    #[cfg(not(feature = "ssr"))]
                    {
                        leptos::logging::log!("Login successful, redirecting to dashboard");
                        // cookie is already set by the server; just navigate
                        use leptos::web_sys;
                        if let Some(window) = web_sys::window() {
                            let _ = window.location().set_href("/dashboard");
                        }
                    }
                }
                Err(e) => {
                    set_error.set(Some(e.to_string()));
                }
            }

            set_loading.set(false);
        });
    };

    view! {
        <div class="page page--center">
            <div class="auth-card glass-card">
                <h1>"Welcome back"</h1>
                <p class="auth-subtitle">
                    "Sign in to access your dashboard and manage your account."
                </p>

                {move || error.get().map(|e| view! { <div class="alert alert-error">{e}</div> })}

                <form on:submit=on_submit class="form">
                    <label class="field">
                        <span class="field-label">"Username"</span>
                        <input
                            type="text"
                            placeholder="Enter your username"
                            on:input=move |ev| set_username.set(event_target_value(&ev))
                            prop:value=move || username.get()
                        />
                    </label>

                    <label class="field">
                        <span class="field-label">"Password"</span>
                        <input
                            type="password"
                            placeholder="••••••••"
                            on:input=move |ev| set_password.set(event_target_value(&ev))
                            prop:value=move || password.get()
                        />
                    </label>

                    <button
                        type="submit"
                        class="btn btn-primary btn-full"
                        class:btn-loading=move || loading.get()
                        disabled=move || loading.get()
                    >
                        {move || if loading.get() { "Logging in..." } else { "Login" }}
                    </button>
                </form>

                <p class="auth-footer">
                    "Don't have an account? "
                    <a href="/register">"Register"</a>
                </p>
            </div>
        </div>
    }
}

#[component]
fn RegisterPage() -> impl IntoView {
    let (username, set_username) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (error, set_error) = signal(None::<String>);
    let (loading, set_loading) = signal(false);

    let on_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        #[cfg(not(feature = "ssr"))]
        leptos::logging::log!("Register form submitted for: {}", username.get());

        set_loading.set(true);
        set_error.set(None);

        let username_val = username.get();
        let password_val = password.get();

        leptos::task::spawn_local(async move {
            let result = register(username_val.clone(), password_val.clone()).await;

            #[cfg(not(feature = "ssr"))]
            leptos::logging::log!("Register result: {:?}", result.is_ok());

            match result {
                Ok(_) => {
                    #[cfg(not(feature = "ssr"))]
                    {
                        leptos::logging::log!("Registration successful, redirecting to login");
                        use leptos::web_sys;
                        if let Some(window) = web_sys::window() {
                            let _ = window.location().set_href("/login");
                        }
                    }
                }
                Err(e) => {
                    set_error.set(Some(e.to_string()));
                }
            }

            set_loading.set(false);
        });
    };

    view! {
        <div class="page page--center">
            <div class="auth-card glass-card">
                <h1>"Create your account"</h1>
                <p class="auth-subtitle">
                    "A simple starter auth flow you can extend and customize."
                </p>

                {move || error.get().map(|e| view! { <div class="alert alert-error">{e}</div> })}

                <form on:submit=on_submit class="form">
                    <label class="field">
                        <span class="field-label">"Username"</span>
                        <input
                            type="text"
                            placeholder="Choose a username"
                            on:input=move |ev| set_username.set(event_target_value(&ev))
                            prop:value=move || username.get()
                        />
                    </label>

                    <label class="field">
                        <span class="field-label">"Password"</span>
                        <input
                            type="password"
                            placeholder="Create a secure password"
                            on:input=move |ev| set_password.set(event_target_value(&ev))
                            prop:value=move || password.get()
                        />
                    </label>

                    <button
                        type="submit"
                        class="btn btn-primary btn-full"
                        class:btn-loading=move || loading.get()
                        disabled=move || loading.get()
                    >
                        {move || if loading.get() { "Creating account..." } else { "Register" }}
                    </button>
                </form>

                <p class="auth-footer">
                    "Already have an account? "
                    <a href="/login">"Login"</a>
                </p>
            </div>
        </div>
    }
}

//
// ─────────────────────────── Dashboard ───────────────────────────
//

#[component]
fn DashboardPage() -> impl IntoView {
    use crate::{CreditCard, UserCards};
    use leptos::logging::log;

    let (username, set_username) = signal(None::<String>);
    let (cards, set_cards) = signal(Vec::<CreditCard>::new());
    let (error, set_error) = signal(None::<String>);
    let (loading, set_loading) = signal(true);

    // Form state for create / edit
    let (editing_id, set_editing_id) = signal(None::<i64>);
    let (brand, set_brand) = signal(String::new());
    let (last4, set_last4) = signal(String::new());
    let (credit_limit, set_credit_limit) = signal(String::new());
    let (current_balance, set_current_balance) = signal(String::new());
    let (nickname, set_nickname) = signal(String::new());
    let (saving, set_saving) = signal(false);

    #[cfg(not(feature = "ssr"))]
    {
        use leptos::task::spawn_local;

        spawn_local({
            let set_username = set_username.clone();
            let set_cards = set_cards.clone();
            let set_error = set_error.clone();
            let set_loading = set_loading.clone();

            async move {
                log!("Dashboard: starting client-side user + cards fetch (cookie-based)");

                match get_user_cards().await {
                    Ok(UserCards { username, cards }) => {
                        log!(
                            "Dashboard: get_user_cards OK for user {}, {} cards",
                            username,
                            cards.len()
                        );
                        set_username.set(Some(username));
                        set_cards.set(cards);
                        set_error.set(None);
                    }
                    Err(e) => {
                        log!("Dashboard: get_user_cards ERROR: {:?}", e);
                        set_error.set(Some(format!("{e}")));
                    }
                }

                set_loading.set(false);
            }
        });
    }

    // Helper: reset form for "new card"
    let reset_form_for_new = {
        let set_editing_id = set_editing_id.clone();
        let set_brand = set_brand.clone();
        let set_last4 = set_last4.clone();
        let set_credit_limit = set_credit_limit.clone();
        let set_current_balance = set_current_balance.clone();
        let set_nickname = set_nickname.clone();

        move || {
            set_editing_id.set(None);
            set_brand.set(String::new());
            set_last4.set(String::new());
            set_credit_limit.set(String::new());
            set_current_balance.set("0".to_string());
            set_nickname.set(String::new());
        }
    };

    // Helper: populate form for editing an existing card
    let start_edit_card = {
        let set_editing_id = set_editing_id.clone();
        let set_brand = set_brand.clone();
        let set_last4 = set_last4.clone();
        let set_credit_limit = set_credit_limit.clone();
        let set_current_balance = set_current_balance.clone();
        let set_nickname = set_nickname.clone();

        move |card: CreditCard| {
            set_editing_id.set(Some(card.id));
            set_brand.set(card.brand);
            set_last4.set(card.last4);
            set_credit_limit.set(card.credit_limit.to_string());
            set_current_balance.set(card.current_balance.to_string());
            set_nickname.set(card.nickname.unwrap_or_default());
        }
    };

    // Save handler (create or update depending on editing_id)
    let on_save = {
        let editing_id = editing_id.clone();
        let brand = brand.clone();
        let last4 = last4.clone();
        let credit_limit = credit_limit.clone();
        let current_balance = current_balance.clone();
        let nickname = nickname.clone();
        let set_cards = set_cards.clone();
        let set_error = set_error.clone();
        let set_saving = set_saving.clone();
        let reset_form_for_new = reset_form_for_new.clone();

        move |ev: web_sys::SubmitEvent| {
            ev.prevent_default();

            #[cfg(not(feature = "ssr"))]
            {
                use leptos::task::spawn_local;

                set_saving.set(true);
                set_error.set(None);

                let editing_id_val = editing_id.get();
                let brand_val = brand.get();
                let last4_val = last4.get();
                let limit_val = credit_limit.get();
                let balance_val = current_balance.get();
                let nickname_val = nickname.get();
                let set_cards = set_cards.clone();
                let set_error = set_error.clone();
                let set_saving = set_saving.clone();
                let reset_form_for_new = reset_form_for_new.clone();

                spawn_local(async move {
                    let credit_limit_i64 = limit_val.parse::<i64>().unwrap_or(0);
                    let current_balance_i64 = balance_val.parse::<i64>().unwrap_or(0);
                    let nickname_opt = if nickname_val.trim().is_empty() {
                        None
                    } else {
                        Some(nickname_val.clone())
                    };

                    let result = if let Some(id) = editing_id_val {
                        update_card(
                            id,
                            brand_val.clone(),
                            last4_val.clone(),
                            credit_limit_i64,
                            current_balance_i64,
                            nickname_opt.clone(),
                        )
                        .await
                    } else {
                        create_card(
                            brand_val.clone(),
                            last4_val.clone(),
                            credit_limit_i64,
                            nickname_opt.clone(),
                        )
                        .await
                    };

                    match result {
                        Ok(card) => {
                            // Merge into local state
                            if let Some(id) = editing_id_val {
                                set_cards.update(|list| {
                                    if let Some(pos) = list.iter().position(|c| c.id == id) {
                                        list[pos] = card.clone();
                                    }
                                });
                            } else {
                                set_cards.update(|list| list.push(card));
                            }

                            reset_form_for_new();
                        }
                        Err(e) => {
                            set_error.set(Some(format!("Save failed: {e}")));
                        }
                    }

                    set_saving.set(false);
                });
            }
        }
    };

    // Delete handler
    let delete_card_action = {
        let set_cards = set_cards.clone();
        let set_error = set_error.clone();

        move |id: i64| {
            #[cfg(not(feature = "ssr"))]
            {
                use leptos::task::spawn_local;

                let set_cards = set_cards.clone();
                let set_error = set_error.clone();

                spawn_local(async move {
                    match delete_card(id).await {
                        Ok(_) => {
                            set_cards.update(|list| {
                                list.retain(|c| c.id != id);
                            });
                        }
                        Err(e) => {
                            set_error.set(Some(format!("Delete failed: {e}")));
                        }
                    }
                });
            }
        }
    };

    view! {
        <div class="page page--center">
            <div class="dashboard-shell">

                // Top line: title + user + logout
                <div class="dashboard-shell-header">
                    <div class="dash-title-block">
                        <p class="dash-eyebrow">"My cards"</p>
                        <h1 class="dash-title">"Credit cards"</h1>
                        {move || username.get().map(|name| view! {
                            <p class="dash-subtitle">
                                "Signed in as " <span class="dash-username">{name}</span>
                            </p>
                        })}
                    </div>

                    <button
                        class="btn btn-ghost btn-sm dash-logout"
                        on:click={
                            let set_username = set_username.clone();
                            let set_error = set_error.clone();
                            move |_| {
                                leptos::task::spawn_local(async move {
                                    let _ = logout_server().await; // ignore error for now
                                    set_username.set(None);
                                    set_error.set(Some("You have been logged out.".to_string()));

                                    #[cfg(not(feature = "ssr"))]
                                    {
                                        use leptos::web_sys;
                                        if let Some(window) = web_sys::window() {
                                            let _ = window.location().set_href("/login");
                                        }
                                    }
                                });
                            }
                        }
                    >
                        "Logout"
                    </button>
                </div>

                // Main card: head with form + list of cards
                <div class="settings-card">

                    // Head: Add / Edit form
                    <div class="cards-head">
                        <div class="cards-head-title">
                            <h2>"Manage cards"</h2>
                            <p>"Create, update or remove your saved credit cards."</p>
                        </div>

                        <form class="cards-form" on:submit=on_save>
                            <div class="cards-form-row">
                                <label class="field">
                                    <span class="field-label">"Brand"</span>
                                    <input
                                        type="text"
                                        placeholder="e.g. HDFC, SBI, Axis"
                                        prop:value=move || brand.get()
                                        on:input=move |ev| set_brand.set(event_target_value(&ev))
                                    />
                                </label>

                                <label class="field">
                                    <span class="field-label">"Last 4 digits"</span>
                                    <input
                                        type="text"
                                        maxlength="4"
                                        placeholder="1234"
                                        prop:value=move || last4.get()
                                        on:input=move |ev| set_last4.set(event_target_value(&ev))
                                    />
                                </label>
                            </div>

                            <div class="cards-form-row">
                                <label class="field">
                                    <span class="field-label">"Credit limit"</span>
                                    <input
                                        type="number"
                                        min="0"
                                        placeholder="100000"
                                        prop:value=move || credit_limit.get()
                                        on:input=move |ev| set_credit_limit.set(event_target_value(&ev))
                                    />
                                </label>

                                <label class="field">
                                    <span class="field-label">"Current balance"</span>
                                    <input
                                        type="number"
                                        min="0"
                                        placeholder="0"
                                        prop:value=move || current_balance.get()
                                        on:input=move |ev| set_current_balance.set(event_target_value(&ev))
                                    />
                                </label>
                            </div>

                            <div class="cards-form-row">
                                <label class="field">
                                    <span class="field-label">"Nickname (optional)"</span>
                                    <input
                                        type="text"
                                        placeholder="e.g. Travel card"
                                        prop:value=move || nickname.get()
                                        on:input=move |ev| set_nickname.set(event_target_value(&ev))
                                    />
                                </label>

                                <div class="cards-form-actions">
                                    <button
                                        type="button"
                                        class="btn btn-ghost btn-sm"
                                        on:click=move |_| reset_form_for_new()
                                    >
                                        "New card"
                                    </button>

                                    <button
                                        type="submit"
                                        class="btn btn-primary btn-sm"
                                        class:btn-loading=move || saving.get()
                                        disabled=move || saving.get()
                                    >
                                        {move || {
                                            if editing_id.get().is_some() {
                                                if saving.get() { "Saving..." } else { "Update card" }
                                            } else {
                                                if saving.get() { "Saving..." } else { "Add card" }
                                            }
                                        }}
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>

                    // Body: list of cards
                    <div class="cards-list">
                        {move || {
                            if let Some(err) = error.get() {
                                view! {
                                    <div class="alert alert-error">{err}</div>
                                }.into_any()
                            } else if loading.get() {
                                view! {
                                    <p class="settings-status">"Loading your cards..."</p>
                                }.into_any()
                            } else if cards.get().is_empty() {
                                view! {
                                    <p class="settings-status">
                                        "No cards yet. Add your first card using the form above."
                                    </p>
                                }.into_any()
                            } else {
                                view! {
                                    <ul class="cards-grid">
                                        <For
                                            each=move || cards.get()
                                            key=|c| c.id
                                            let:card
                                        >
                                            <li class="card-tile">
                                                <div class="card-tile-header">
                                                    <div>
                                                        <p class="card-tile-title">
                                                            {card.nickname.clone().unwrap_or_else(|| card.brand.clone())}
                                                        </p>
                                                        <p class="card-tile-subtitle">
                                                            {card.brand.clone()} " • •••• " {card.last4.clone()}
                                                        </p>
                                                    </div>
                                                    <div class="card-tile-actions">
                                                        <button
                                                            class="btn btn-ghost btn-xs"
                                                            on:click={
                                                                let card = card.clone();
                                                                move |_| start_edit_card(card.clone())
                                                            }
                                                        >
                                                            "Edit"
                                                        </button>
                                                        <button
                                                            class="btn btn-ghost btn-xs btn-danger"
                                                            on:click={
                                                                let id = card.id;
                                                                move |_| delete_card_action(id)
                                                            }
                                                        >
                                                            "Delete"
                                                        </button>
                                                    </div>
                                                </div>

                                                <div class="card-tile-body">
                                                    <p>
                                                        <span class="card-tile-label">"Limit"</span>
                                                        <span class="card-tile-value">{"₹"}{card.credit_limit}</span>
                                                    </p>
                                                    <p>
                                                        <span class="card-tile-label">"Balance"</span>
                                                        <span class="card-tile-value">{"₹"}{card.current_balance}</span>
                                                    </p>
                                                </div>
                                            </li>
                                        </For>
                                    </ul>
                                }.into_any()
                            }
                        }}
                    </div>

                    // Tiny footer text
                    <div class="settings-footer">
                        <span class="settings-status settings-status--ok">
                            "Data is loaded from your database · JWT protected"
                        </span>
                    </div>
                </div>
            </div>
        </div>
    }
}

//
// ───────────────────── Cards server functions ─────────────────────
//

#[server(GetUserCards, "/api")]
pub async fn get_user_cards() -> Result<UserCards, ServerFnError> {
    use crate::auth::verify_token;
    use crate::db::{get_db_pool, list_cards_for_user};

    #[cfg(feature = "ssr")]
    {
        log::info!("GetUserCards: called, will verify cookie token & load cards");

        let token = token_from_cookie().await?;
        let claims =
            verify_token(&token).map_err(|e| ServerFnError::new(format!("Auth error: {e}")))?;

        let pool = get_db_pool()
            .await
            .map_err(|e| ServerFnError::new(format!("Database error: {e}")))?;

        let cards_db = list_cards_for_user(&pool, &claims.sub)
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to load cards: {e}")))?;

        let cards = cards_db.into_iter().map(CreditCard::from).collect();

        Ok(UserCards {
            username: claims.sub,
            cards,
        })
    }

    #[cfg(not(feature = "ssr"))]
    unreachable!()
}

#[server(CreateCard, "/api")]
pub async fn create_card(
    brand: String,
    last4: String,
    credit_limit: i64,
    nickname: Option<String>,
) -> Result<CreditCard, ServerFnError> {
    use crate::auth::verify_token;
    use crate::db::{get_db_pool, insert_card_for_user};

    #[cfg(feature = "ssr")]
    {
        let token = token_from_cookie().await?;
        let claims =
            verify_token(&token).map_err(|e| ServerFnError::new(format!("Auth error: {e}")))?;

        let pool = get_db_pool()
            .await
            .map_err(|e| ServerFnError::new(format!("Database error: {e}")))?;

        let card_db =
            insert_card_for_user(&pool, &claims.sub, &brand, &last4, credit_limit, nickname)
                .await
                .map_err(|e| ServerFnError::new(format!("Failed to create card: {e}")))?;

        Ok(CreditCard::from(card_db))
    }

    #[cfg(not(feature = "ssr"))]
    unreachable!()
}

#[server(UpdateCard, "/api")]
pub async fn update_card(
    id: i64,
    brand: String,
    last4: String,
    credit_limit: i64,
    current_balance: i64,
    nickname: Option<String>,
) -> Result<CreditCard, ServerFnError> {
    use crate::auth::verify_token;
    use crate::db::{get_db_pool, update_card_for_user};

    #[cfg(feature = "ssr")]
    {
        let token = token_from_cookie().await?;
        let claims =
            verify_token(&token).map_err(|e| ServerFnError::new(format!("Auth error: {e}")))?;

        let pool = get_db_pool()
            .await
            .map_err(|e| ServerFnError::new(format!("Database error: {e}")))?;

        let card_db = update_card_for_user(
            &pool,
            &claims.sub,
            id,
            &brand,
            &last4,
            credit_limit,
            current_balance,
            nickname,
        )
        .await
        .map_err(|e| ServerFnError::new(format!("Failed to update card: {e}")))?;

        Ok(CreditCard::from(card_db))
    }

    #[cfg(not(feature = "ssr"))]
    unreachable!()
}

#[server(DeleteCard, "/api")]
pub async fn delete_card(id: i64) -> Result<(), ServerFnError> {
    use crate::auth::verify_token;
    use crate::db::{delete_card_for_user, get_db_pool};

    #[cfg(feature = "ssr")]
    {
        let token = token_from_cookie().await?;
        let claims =
            verify_token(&token).map_err(|e| ServerFnError::new(format!("Auth error: {e}")))?;

        let pool = get_db_pool()
            .await
            .map_err(|e| ServerFnError::new(format!("Database error: {e}")))?;

        delete_card_for_user(&pool, &claims.sub, id)
            .await
            .map_err(|e| ServerFnError::new(format!("Failed to delete card: {e}")))?;

        Ok(())
    }

    #[cfg(not(feature = "ssr"))]
    unreachable!()
}

//
// ───────────────────── Server functions & types ─────────────────────
//

#[server(Login, "/api")]
pub async fn login(username: String, password: String) -> Result<(), ServerFnError> {
    use crate::auth::authenticate_user;
    use crate::db::get_db_pool;

    log::info!("Login attempt for user: {}", username);

    let pool = get_db_pool()
        .await
        .map_err(|e| ServerFnError::new(format!("Database error: {}", e)))?;

    let token = authenticate_user(&pool, &username, &password)
        .await
        .map_err(|e| {
            log::warn!("Login failed for {}: {}", username, e);
            ServerFnError::new(e)
        })?;

    log::info!("Login successful for user: {}", username);

    // --- NEW: set HttpOnly cookie (SSR only) ---
    #[cfg(feature = "ssr")]
    {
        use cookie::{Cookie, SameSite};
        use http::header;
        use leptos::prelude::*;
        use leptos_axum::ResponseOptions;

        let response = expect_context::<ResponseOptions>();

        let cookie = Cookie::build(("auth_token", token))
            .path("/") // send on all paths
            .http_only(true) // JS can't read it
            .same_site(SameSite::Lax)
            .secure(false) // TODO: set to true in HTTPS/prod
            .build();

        if let Ok(value) = http::HeaderValue::from_str(&cookie.to_string()) {
            response.insert_header(header::SET_COOKIE, value);
        } else {
            log::error!("Failed to convert auth cookie to HeaderValue");
            return Err(ServerFnError::new("Internal error setting cookie"));
        }
    }

    Ok(())
}

#[server(Register, "/api")]
pub async fn register(username: String, password: String) -> Result<(), ServerFnError> {
    use crate::auth::create_user;
    use crate::db::get_db_pool;

    log::info!("Registration attempt for user: {}", username);

    let pool = get_db_pool()
        .await
        .map_err(|e| ServerFnError::new(format!("Database error: {}", e)))?;

    create_user(&pool, &username, &password)
        .await
        .map_err(|e| {
            log::warn!("Registration failed for {}: {}", username, e);
            ServerFnError::new(e)
        })?;

    log::info!("Registration successful for user: {}", username);
    Ok(())
}

#[server(GetUserInfo, "/api")]
pub async fn get_user_info() -> Result<UserInfo, ServerFnError> {
    use crate::auth::verify_token;

    #[cfg(feature = "ssr")]
    {
        let token = token_from_cookie().await?;
        log::info!("GetUserInfo: called with cookie token");

        match verify_token(&token) {
            Ok(claims) => {
                log::info!("GetUserInfo: token valid for user {}", claims.sub);
                Ok(UserInfo {
                    username: claims.sub,
                })
            }
            Err(e) => {
                log::warn!("GetUserInfo: verify_token failed: {}", e);
                Err(ServerFnError::new(e))
            }
        }
    }

    #[cfg(not(feature = "ssr"))]
    unreachable!()
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UserInfo {
    pub username: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CreditCard {
    pub id: i64,
    pub brand: String,
    pub last4: String,
    pub credit_limit: i64,
    pub current_balance: i64,
    pub nickname: Option<String>,
}

#[cfg(feature = "ssr")]
impl From<crate::db::CreditCard> for CreditCard {
    fn from(db: crate::db::CreditCard) -> Self {
        CreditCard {
            id: db.id,
            brand: db.brand,
            last4: db.last4,
            credit_limit: db.credit_limit,
            current_balance: db.current_balance,
            nickname: db.nickname,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UserCards {
    pub username: String,
    pub cards: Vec<CreditCard>,
}
