type EnvvarType = 'PORT' |
  'TZ' |
  'ENVIRONMENT' |
  'JWT_PRIVATE_KEY' |
  'JWT_PUBLIC_KEY' |
  'COOKIE_DOMAIN' |
  'GOOGLE_CLIENT_ID' |
  'GOOGLE_CLIENT_SECRET' |
  'GOOGLE_CALLBACK_URL' |
  'SENDGRID_API_KEY' |
  'SENDGRID_EMAIL_VERIFICATION_TEMPLATE_ID' |
  'DOCS_URL' |
  'APP_URL';

type EnvvarResult = {
  value: string;
  error?: string;
}

export const getEnvvarValue = (envVarName: EnvvarType, required: boolean, callback?: (error: string) => void) => {
  const result: EnvvarResult = {
    value: '',
  };
  if (required && !process.env[envVarName]) {
    if (callback) {
      callback(`Missing environment variable ${envVarName}`);
    }
    result.error = `Missing environment variable ${envVarName}`;
  } else {
    result.value = process.env[envVarName] ||
      '';
  }

  return result;
};
