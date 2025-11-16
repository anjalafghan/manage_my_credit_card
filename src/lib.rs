use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::{components::*, *};

#[cfg(feature = "ssr")]
pub mod auth;
#[cfg(feature = "ssr")]
pub mod db;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/manage_my_credit_card.css"/>
        <Title text="Leptos Auth Demo"/>
        <Router>
            <main>
                <Routes fallback=|| "Page not found".into_view()>
                    <Route path=StaticSegment("") view=HomePage/>
                    <Route path=StaticSegment("login") view=LoginPage/>
                    <Route path=StaticSegment("register") view=RegisterPage/>
                    <Route path=StaticSegment("dashboard") view=DashboardPage/>
                </Routes>
            </main>
        </Router>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    view! {
        <div class="container">
            <h1>"Welcome to Leptos Auth Demo"</h1>
            <div class="links">
                <a href="/login">"Login"</a>
                <a href="/register">"Register"</a>
            </div>
        </div>
    }
}

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
                Ok(_token) => {
                    #[cfg(not(feature = "ssr"))]
                    {
                        use leptos::web_sys;
                        leptos::logging::log!("Login successful, storing token");
                        let window = web_sys::window().unwrap();
                        let storage = window.local_storage().unwrap().unwrap();
                        let _ = storage.set_item("token", &_token);

                        let location = window.location();
                        let _ = location.set_href("/dashboard");
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
        <div class="container">
            <div class="form-container">
                <h1>"Login"</h1>
                {move || error.get().map(|e| view! { <div class="error">{e}</div> })}
                <form on:submit=on_submit>
                    <input
                        type="text"
                        placeholder="Username"
                        on:input=move |ev| set_username.set(event_target_value(&ev))
                        prop:value=move || username.get()
                    />
                    <input
                        type="password"
                        placeholder="Password"
                        on:input=move |ev| set_password.set(event_target_value(&ev))
                        prop:value=move || password.get()
                    />
                    <button type="submit" disabled=move || loading.get()>
                        {move || if loading.get() { "Loading..." } else { "Login" }}
                    </button>
                </form>
                <p>"Don't have an account? " <a href="/register">"Register"</a></p>
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
                        use leptos::web_sys;
                        leptos::logging::log!("Registration successful, redirecting to login");
                        let window = web_sys::window().unwrap();
                        let location = window.location();
                        let _ = location.set_href("/login");
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
        <div class="container">
            <div class="form-container">
                <h1>"Register"</h1>
                {move || error.get().map(|e| view! { <div class="error">{e}</div> })}
                <form on:submit=on_submit>
                    <input
                        type="text"
                        placeholder="Username"
                        on:input=move |ev| set_username.set(event_target_value(&ev))
                        prop:value=move || username.get()
                    />
                    <input
                        type="password"
                        placeholder="Password"
                        on:input=move |ev| set_password.set(event_target_value(&ev))
                        prop:value=move || password.get()
                    />
                    <button type="submit" disabled=move || loading.get()>
                        {move || if loading.get() { "Loading..." } else { "Register" }}
                    </button>
                </form>
                <p>"Already have an account? " <a href="/login">"Login"</a></p>
            </div>
        </div>
    }
}

#[component]
fn DashboardPage() -> impl IntoView {
    let user_info = Resource::new(|| (), |_| async move { get_user_info().await });

    view! {
        <div class="container">
            <div class="dashboard">
                <h1>"Dashboard"</h1>
                <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                    {move || Suspend::new(async move {
                        match user_info.await {
                            Ok(info) => view! {
                                <div>
                                    <p>"Welcome, " {info.username} "!"</p>
                                    <button on:click=move |_| {
                                        #[cfg(not(feature = "ssr"))]
                                        {
                                            use leptos::web_sys;
                                            let window = web_sys::window().unwrap();
                                            let storage = window.local_storage().unwrap().unwrap();
                                            let _ = storage.remove_item("token");
                                            let location = window.location();
                                            let _ = location.set_href("/login");
                                        }
                                    }>"Logout"</button>
                                </div>
                            }.into_any(),
                            Err(_) => {
                                #[cfg(not(feature = "ssr"))]
                                {
                                    use leptos::web_sys;
                                    let window = web_sys::window().unwrap();
                                    let location = window.location();
                                    let _ = location.set_href("/login");
                                }
                                view! { <p>"Redirecting to login..."</p> }.into_any()
                            }
                        }
                    })}
                </Suspense>
            </div>
        </div>
    }
}

#[server(Login, "/api")]
pub async fn login(username: String, password: String) -> Result<String, ServerFnError> {
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
    Ok(token)
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
    use axum::http::HeaderMap;
    use leptos_axum::extract;

    let headers: HeaderMap = extract().await?;

    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ServerFnError::new("No token provided"))?;

    let claims = verify_token(token).map_err(|e| ServerFnError::new(e))?;

    Ok(UserInfo {
        username: claims.sub,
    })
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UserInfo {
    pub username: String,
}
