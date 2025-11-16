// At the top of main.rs:

#[cfg(feature = "ssr")]
use axum::Router;
#[cfg(feature = "ssr")]
use leptos::config::get_configuration;
#[cfg(feature = "ssr")]
use leptos::hydration::{AutoReload, HydrationScripts};
#[cfg(feature = "ssr")]
use leptos::prelude::*;
#[cfg(feature = "ssr")]
use leptos_axum::{generate_route_list, LeptosRoutes};
#[cfg(feature = "ssr")]
use leptos_meta::MetaTags;
#[cfg(feature = "ssr")]
use manage_my_credit_card::App;
#[cfg(feature = "ssr")]
use tower_http::services::ServeDir;

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .expect("couldn't initialize logging");

    // Initialize database
    manage_my_credit_card::db::get_db_pool()
        .await
        .expect("Failed to initialize database");

    let conf = get_configuration(None).unwrap();
    let addr = conf.leptos_options.site_addr;
    let leptos_options = conf.leptos_options;
    let routes = generate_route_list(App);
    let site_root = leptos_options.site_root.to_string();

    let app = Router::new()
        .leptos_routes(&leptos_options, routes, {
            let leptos_options = leptos_options.clone();
            move || shell(leptos_options.clone())
        })
        .fallback_service(ServeDir::new(&site_root))
        .with_state(leptos_options);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    log::info!("listening on http://{}", &addr);
    log::info!("Server functions registered");
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

#[cfg(feature = "ssr")]
fn shell(options: leptos::config::LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone() />
                <MetaTags/>
                <HydrationScripts options/>
                <link rel="stylesheet" id="leptos" href="/pkg/manage_my_credit_card.css"/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

#[cfg(not(feature = "ssr"))]
pub fn main() {
    // no client-side main function
}
