/**
 * Environment-variable-backed secret store.
 *
 * Sensitive credentials (SMTP_PASSWORD, SLACK_WEBHOOK_URL, THREATLENS_API_KEY)
 * are read from and written to process.env at runtime.  On managed platforms
 * that inject secrets as environment variables (e.g. via a secrets panel or
 * .env file), they will already be present at startup.  Values set via the
 * Settings UI persist only for the lifetime of the current process; to make
 * them survive restarts, set the corresponding environment variable in your
 * deployment environment.
 */

/** Write a secret into process.env for the current process lifetime. */
export async function setSecret(name: string, value: string): Promise<void> {
  process.env[name] = value;
}

/** Read a secret from process.env. */
export async function getSecret(name: string): Promise<string> {
  return process.env[name] ?? "";
}

/** Clear a secret from process.env. */
export async function deleteSecret(name: string): Promise<void> {
  delete process.env[name];
}

/**
 * No-op on this implementation — secrets are already available in process.env
 * if set by the deployment environment.
 */
export async function loadSecretsIntoEnv(): Promise<void> {
  // Secrets come from the process environment; nothing to load.
}
