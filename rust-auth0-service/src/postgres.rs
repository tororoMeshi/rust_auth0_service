use sqlx::error::DatabaseError;
use sqlx::{PgPool, Row};

use crate::auth_foundation::{sha256_digest, sha256_digest_eq};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedService {
    pub(crate) service_id: String,
    pub(crate) login_callback_uri: String,
    pub(crate) logout_return_uri: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PostgresAuthError {
    ServiceNotFound,
    ServiceDisabled,
    ServiceSecretMismatch,
    UserDisabled,
    DatabaseFailure,
    StoredSecretInvalidLength,
    IdentityInconsistent,
}

pub(crate) async fn authenticate_service(
    pool: &PgPool,
    service_id: &str,
    presented_service_secret: &str,
) -> Result<AuthenticatedService, PostgresAuthError> {
    let Some((service_id, is_enabled, login_callback_uri, logout_return_uri, stored_secret)) =
        read_registered_service(pool, service_id).await?
    else {
        return Err(PostgresAuthError::ServiceNotFound);
    };

    if !is_enabled {
        return Err(PostgresAuthError::ServiceDisabled);
    }

    let stored_digest = stored_secret_digest(&stored_secret)?;
    let presented_digest = sha256_digest(presented_service_secret.as_bytes());
    if !sha256_digest_eq(&stored_digest, &presented_digest) {
        return Err(PostgresAuthError::ServiceSecretMismatch);
    }

    Ok(AuthenticatedService {
        service_id,
        login_callback_uri,
        logout_return_uri,
    })
}

pub(crate) async fn lookup_login_callback_uri(
    pool: &PgPool,
    service_id: &str,
) -> Result<String, PostgresAuthError> {
    let row = sqlx::query(
        "SELECT is_enabled, login_callback_uri
         FROM public.registered_web_services
         WHERE service_id = $1",
    )
    .bind(service_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| PostgresAuthError::DatabaseFailure)?;

    let Some(row) = row else {
        return Err(PostgresAuthError::ServiceNotFound);
    };
    let is_enabled: bool = row
        .try_get("is_enabled")
        .map_err(|_| PostgresAuthError::DatabaseFailure)?;
    if !is_enabled {
        return Err(PostgresAuthError::ServiceDisabled);
    }
    row.try_get("login_callback_uri")
        .map_err(|_| PostgresAuthError::DatabaseFailure)
}

pub(crate) async fn read_internal_user_enabled(
    pool: &PgPool,
    internal_user_id: i32,
) -> Result<Option<bool>, PostgresAuthError> {
    let row = sqlx::query(
        "SELECT is_enabled
         FROM public.internal_users
         WHERE internal_user_id = $1",
    )
    .bind(internal_user_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| PostgresAuthError::DatabaseFailure)?;

    row.map(|row| {
        row.try_get("is_enabled")
            .map_err(|_| PostgresAuthError::DatabaseFailure)
    })
    .transpose()
}

pub(crate) async fn resolve_external_identity(
    pool: &PgPool,
    provider: &str,
    subject: &str,
) -> Result<i32, PostgresAuthError> {
    match read_external_identity_with_user(pool, provider, subject).await? {
        Some((internal_user_id, Some(true))) => Ok(internal_user_id),
        Some((_, Some(false))) => Err(PostgresAuthError::UserDisabled),
        Some((_, None)) => Err(PostgresAuthError::IdentityInconsistent),
        None => create_external_identity(pool, provider, subject).await,
    }
}

async fn read_registered_service(
    pool: &PgPool,
    service_id: &str,
) -> Result<Option<(String, bool, String, String, Vec<u8>)>, PostgresAuthError> {
    let row = sqlx::query(
        "SELECT
            service_id,
            is_enabled,
            login_callback_uri,
            logout_return_uri,
            service_secret_sha256
         FROM public.registered_web_services
         WHERE service_id = $1",
    )
    .bind(service_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| PostgresAuthError::DatabaseFailure)?;

    row.map(|row| {
        Ok((
            row.try_get("service_id")
                .map_err(|_| PostgresAuthError::DatabaseFailure)?,
            row.try_get("is_enabled")
                .map_err(|_| PostgresAuthError::DatabaseFailure)?,
            row.try_get("login_callback_uri")
                .map_err(|_| PostgresAuthError::DatabaseFailure)?,
            row.try_get("logout_return_uri")
                .map_err(|_| PostgresAuthError::DatabaseFailure)?,
            row.try_get("service_secret_sha256")
                .map_err(|_| PostgresAuthError::DatabaseFailure)?,
        ))
    })
    .transpose()
}

async fn read_external_identity_with_user(
    pool: &PgPool,
    provider: &str,
    subject: &str,
) -> Result<Option<(i32, Option<bool>)>, PostgresAuthError> {
    let row = sqlx::query(
        "SELECT
            ei.internal_user_id,
            iu.is_enabled
         FROM public.external_identities AS ei
         LEFT JOIN public.internal_users AS iu
           ON iu.internal_user_id = ei.internal_user_id
         WHERE ei.provider = $1
           AND ei.subject = $2",
    )
    .bind(provider)
    .bind(subject)
    .fetch_optional(pool)
    .await
    .map_err(|_| PostgresAuthError::DatabaseFailure)?;

    row.map(|row| {
        Ok((
            row.try_get("internal_user_id")
                .map_err(|_| PostgresAuthError::DatabaseFailure)?,
            row.try_get("is_enabled")
                .map_err(|_| PostgresAuthError::DatabaseFailure)?,
        ))
    })
    .transpose()
}

async fn create_external_identity(
    pool: &PgPool,
    provider: &str,
    subject: &str,
) -> Result<i32, PostgresAuthError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| PostgresAuthError::DatabaseFailure)?;

    let internal_user_row = match sqlx::query(
        "INSERT INTO public.internal_users DEFAULT VALUES
         RETURNING internal_user_id",
    )
    .fetch_one(&mut *transaction)
    .await
    {
        Ok(row) => row,
        Err(_) => {
            let _ = transaction.rollback().await;
            return Err(PostgresAuthError::DatabaseFailure);
        }
    };

    let internal_user_id: i32 = match internal_user_row.try_get("internal_user_id") {
        Ok(internal_user_id) => internal_user_id,
        Err(_) => {
            let _ = transaction.rollback().await;
            return Err(PostgresAuthError::DatabaseFailure);
        }
    };

    match sqlx::query(
        "INSERT INTO public.external_identities (
            provider,
            subject,
            internal_user_id
         )
         VALUES ($1, $2, $3)",
    )
    .bind(provider)
    .bind(subject)
    .bind(internal_user_id)
    .execute(&mut *transaction)
    .await
    {
        Ok(_) => transaction
            .commit()
            .await
            .map(|_| internal_user_id)
            .map_err(|_| PostgresAuthError::DatabaseFailure),
        Err(error) => {
            let is_unique_conflict = is_external_identity_unique_violation(&error);
            if transaction.rollback().await.is_err() {
                return Err(PostgresAuthError::DatabaseFailure);
            }

            if !is_unique_conflict {
                return Err(PostgresAuthError::DatabaseFailure);
            }

            match read_external_identity_with_user(pool, provider, subject).await? {
                Some((internal_user_id, Some(true))) => Ok(internal_user_id),
                Some((_, Some(false))) => Err(PostgresAuthError::UserDisabled),
                Some((_, None)) | None => Err(PostgresAuthError::IdentityInconsistent),
            }
        }
    }
}

fn stored_secret_digest(stored_secret: &[u8]) -> Result<[u8; 32], PostgresAuthError> {
    stored_secret
        .try_into()
        .map_err(|_| PostgresAuthError::StoredSecretInvalidLength)
}

fn is_external_identity_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database_error)
            if database_error.code().as_deref() == Some("23505")
                && database_error.constraint() == Some("external_identities_pkey")
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use sqlx::postgres::PgPoolOptions;
    use sqlx::{PgPool, Row};

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_suffix() -> String {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after UNIX epoch")
            .as_nanos();
        format!("{nanos}_{sequence}")
    }

    fn test_database_url() -> String {
        std::env::var("AUTH_FOUNDATION_TEST_DATABASE_URL")
            .expect("AUTH_FOUNDATION_TEST_DATABASE_URL must be set for ignored PostgreSQL tests")
    }

    async fn test_pool() -> PgPool {
        PgPoolOptions::new()
            .max_connections(8)
            .connect(&test_database_url())
            .await
            .expect("connect to disposable PostgreSQL")
    }

    async fn cleanup_service(pool: &PgPool, service_id: &str) {
        sqlx::query("DELETE FROM public.registered_web_services WHERE service_id = $1")
            .bind(service_id)
            .execute(pool)
            .await
            .expect("clean up registered service");
    }

    async fn cleanup_identity(pool: &PgPool, provider: &str) {
        sqlx::query(
            "WITH deleted_identities AS (
                DELETE FROM public.external_identities
                WHERE provider = $1
                RETURNING internal_user_id
             )
             DELETE FROM public.internal_users
             WHERE internal_user_id IN (
                 SELECT internal_user_id FROM deleted_identities
             )",
        )
        .bind(provider)
        .execute(pool)
        .await
        .expect("clean up external identities and internal users");
    }

    async fn insert_service(pool: &PgPool, service_id: &str, is_enabled: bool, secret: &str) {
        sqlx::query(
            "INSERT INTO public.registered_web_services (
                service_id,
                is_enabled,
                login_callback_uri,
                logout_return_uri,
                service_secret_sha256
             )
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(service_id)
        .bind(is_enabled)
        .bind("https://callback.example.test")
        .bind("https://logout.example.test")
        .bind(sha256_digest(secret.as_bytes()).to_vec())
        .execute(pool)
        .await
        .expect("insert registered service");
    }

    #[test]
    fn stored_secret_digest_accepts_32_bytes() {
        let digest = sha256_digest(b"service-secret");
        assert_eq!(stored_secret_digest(&digest), Ok(digest));
    }

    #[test]
    fn stored_secret_digest_rejects_31_bytes() {
        assert_eq!(
            stored_secret_digest(&[0_u8; 31]),
            Err(PostgresAuthError::StoredSecretInvalidLength)
        );
    }

    #[test]
    fn stored_secret_digest_rejects_33_bytes() {
        assert_eq!(
            stored_secret_digest(&[0_u8; 33]),
            Err(PostgresAuthError::StoredSecretInvalidLength)
        );
    }

    #[test]
    fn stored_secret_digest_matches_presented_secret_digest() {
        let stored = stored_secret_digest(&sha256_digest(b"service-secret"))
            .expect("32 byte SHA-256 digest");
        assert!(sha256_digest_eq(&stored, &sha256_digest(b"service-secret")));
    }

    #[test]
    fn stored_secret_digest_rejects_different_presented_secret_digest() {
        let stored = stored_secret_digest(&sha256_digest(b"service-secret"))
            .expect("32 byte SHA-256 digest");
        assert!(!sha256_digest_eq(
            &stored,
            &sha256_digest(b"different-secret")
        ));
    }

    #[actix_web::test]
    #[ignore = "requires disposable PostgreSQL"]
    async fn registered_service_authentication_cases() {
        let pool = test_pool().await;
        let service_id = format!("t06service_{}", test_suffix());
        insert_service(&pool, &service_id, true, "correct-secret").await;

        let authenticated = authenticate_service(&pool, &service_id, "correct-secret")
            .await
            .expect("enabled service authenticates");
        assert_eq!(authenticated.service_id, service_id);
        assert_eq!(
            authenticated.login_callback_uri,
            "https://callback.example.test"
        );
        assert_eq!(
            authenticated.logout_return_uri,
            "https://logout.example.test"
        );
        assert_eq!(
            authenticate_service(&pool, "t06missing", "correct-secret").await,
            Err(PostgresAuthError::ServiceNotFound)
        );
        assert_eq!(
            authenticate_service(&pool, &service_id, "wrong-secret").await,
            Err(PostgresAuthError::ServiceSecretMismatch)
        );

        sqlx::query(
            "UPDATE public.registered_web_services SET is_enabled = false WHERE service_id = $1",
        )
        .bind(&service_id)
        .execute(&pool)
        .await
        .expect("disable registered service");
        assert_eq!(
            authenticate_service(&pool, &service_id, "correct-secret").await,
            Err(PostgresAuthError::ServiceDisabled)
        );

        cleanup_service(&pool, &service_id).await;
    }

    #[actix_web::test]
    #[ignore = "requires disposable PostgreSQL"]
    async fn login_callback_lookup_cases() {
        let pool = test_pool().await;
        let service_id = format!("t10login{}", test_suffix());
        insert_service(&pool, &service_id, true, "secret").await;

        assert_eq!(
            lookup_login_callback_uri(&pool, &service_id).await,
            Ok("https://callback.example.test".to_owned())
        );
        assert_eq!(
            lookup_login_callback_uri(&pool, "t10missing").await,
            Err(PostgresAuthError::ServiceNotFound)
        );
        sqlx::query(
            "UPDATE public.registered_web_services SET is_enabled = false WHERE service_id = $1",
        )
        .bind(&service_id)
        .execute(&pool)
        .await
        .expect("disable service");
        assert_eq!(
            lookup_login_callback_uri(&pool, &service_id).await,
            Err(PostgresAuthError::ServiceDisabled)
        );
        cleanup_service(&pool, &service_id).await;

        pool.close().await;
        assert_eq!(
            lookup_login_callback_uri(&pool, "t10closed").await,
            Err(PostgresAuthError::DatabaseFailure)
        );
    }

    #[actix_web::test]
    #[ignore = "requires disposable PostgreSQL"]
    async fn internal_user_enabled_read_cases() {
        let pool = test_pool().await;
        let enabled: i32 = sqlx::query(
            "INSERT INTO public.internal_users DEFAULT VALUES RETURNING internal_user_id",
        )
        .fetch_one(&pool)
        .await
        .expect("insert enabled user")
        .try_get("internal_user_id")
        .expect("user id");
        let disabled: i32 = sqlx::query("INSERT INTO public.internal_users (is_enabled) VALUES (false) RETURNING internal_user_id")
            .fetch_one(&pool).await.expect("insert disabled user").try_get("internal_user_id").expect("user id");
        assert_eq!(
            read_internal_user_enabled(&pool, enabled).await,
            Ok(Some(true))
        );
        assert_eq!(
            read_internal_user_enabled(&pool, disabled).await,
            Ok(Some(false))
        );
        assert_eq!(read_internal_user_enabled(&pool, -1).await, Ok(None));
        sqlx::query("DELETE FROM public.internal_users WHERE internal_user_id = $1 OR internal_user_id = $2")
            .bind(enabled).bind(disabled).execute(&pool).await.expect("clean up users");
    }

    #[actix_web::test]
    #[ignore = "requires disposable PostgreSQL"]
    async fn external_identity_resolution_cases() {
        let pool = test_pool().await;
        let provider = format!("t06provider_{}", test_suffix());
        let first = resolve_external_identity(&pool, &provider, "subject-one")
            .await
            .expect("create first identity");
        assert_eq!(
            resolve_external_identity(&pool, &provider, "subject-one").await,
            Ok(first)
        );
        let second = resolve_external_identity(&pool, &provider, "subject-two")
            .await
            .expect("same provider different subject creates another user");
        let third = resolve_external_identity(&pool, "t06otherprovider", "subject-one")
            .await
            .expect("different provider same subject creates another user");
        assert_ne!(first, second);
        assert_ne!(first, third);

        sqlx::query(
            "UPDATE public.internal_users SET is_enabled = false WHERE internal_user_id = $1",
        )
        .bind(first)
        .execute(&pool)
        .await
        .expect("disable internal user");
        assert_eq!(
            resolve_external_identity(&pool, &provider, "subject-one").await,
            Err(PostgresAuthError::UserDisabled)
        );

        cleanup_identity(&pool, &provider).await;
        cleanup_identity(&pool, "t06otherprovider").await;
    }

    #[actix_web::test]
    #[ignore = "requires disposable PostgreSQL"]
    async fn closed_pool_is_database_failure() {
        let pool = test_pool().await;
        pool.close().await;
        assert_eq!(
            authenticate_service(&pool, "t06service", "secret").await,
            Err(PostgresAuthError::DatabaseFailure)
        );
        assert_eq!(
            resolve_external_identity(&pool, "t06provider", "subject").await,
            Err(PostgresAuthError::DatabaseFailure)
        );
    }

    #[actix_web::test]
    #[ignore = "requires disposable PostgreSQL"]
    async fn concurrent_identity_resolution_returns_one_internal_user() {
        let pool = test_pool().await;
        let provider = format!("t06provider_{}", test_suffix());
        let subject = "concurrent-subject".to_owned();
        let users_before: i64 = sqlx::query("SELECT count(*) AS count FROM public.internal_users")
            .fetch_one(&pool)
            .await
            .expect("count internal users before concurrent resolution")
            .try_get("count")
            .expect("decode initial user count");
        let first_pool = pool.clone();
        let first_provider = provider.clone();
        let first_subject = subject.clone();
        let first = actix_web::rt::spawn(async move {
            resolve_external_identity(&first_pool, &first_provider, &first_subject).await
        });
        let second_pool = pool.clone();
        let second_provider = provider.clone();
        let second = actix_web::rt::spawn(async move {
            resolve_external_identity(&second_pool, &second_provider, &subject).await
        });

        let first_id = first
            .await
            .expect("first task joins")
            .expect("first resolves");
        let second_id = second
            .await
            .expect("second task joins")
            .expect("second resolves");
        assert_eq!(first_id, second_id);

        let identity_count: i64 = sqlx::query(
            "SELECT count(*) AS count FROM public.external_identities WHERE provider = $1",
        )
        .bind(&provider)
        .fetch_one(&pool)
        .await
        .expect("count external identities")
        .try_get("count")
        .expect("decode identity count");
        let users_after: i64 = sqlx::query("SELECT count(*) AS count FROM public.internal_users")
            .fetch_one(&pool)
            .await
            .expect("count internal users after concurrent resolution")
            .try_get("count")
            .expect("decode final user count");
        assert_eq!(identity_count, 1);
        assert_eq!(users_after, users_before + 1);

        cleanup_identity(&pool, &provider).await;
    }

    #[actix_web::test]
    #[ignore = "requires disposable PostgreSQL"]
    async fn unique_conflict_rolls_back_extra_internal_user_and_returns_winner() {
        let pool = test_pool().await;
        let provider = format!("t06provider_{}", test_suffix());
        let subject = "unique-conflict-subject";
        let winner = resolve_external_identity(&pool, &provider, subject)
            .await
            .expect("create committed identity");
        let before: i64 = sqlx::query("SELECT count(*) AS count FROM public.internal_users")
            .fetch_one(&pool)
            .await
            .expect("count internal users before conflict")
            .try_get("count")
            .expect("decode user count before conflict");

        assert_eq!(
            create_external_identity(&pool, &provider, subject).await,
            Ok(winner)
        );

        let after: i64 = sqlx::query("SELECT count(*) AS count FROM public.internal_users")
            .fetch_one(&pool)
            .await
            .expect("count internal users after conflict")
            .try_get("count")
            .expect("decode user count after conflict");
        assert_eq!(after, before);

        cleanup_identity(&pool, &provider).await;
    }
}
