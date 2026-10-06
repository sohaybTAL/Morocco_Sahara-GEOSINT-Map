import { next } from '@vercel/functions';

export const config = {
  matcher: '/(.*)',
};

export default function middleware(req) {
  const basicAuth = req.headers.get('authorization');

  if (basicAuth) {
    try {
      const authValue = basicAuth.split(' ')[1];
      if (!authValue) throw new Error('Missing auth value');

      // Decode the base64 string
      const decoded = atob(authValue);
      const [user, pwd] = decoded.split(':');

      const validUser = process.env.ADMIN_USERNAME;
      const validPwd = process.env.ADMIN_PASSWORD;

      // Fail-closed: Ensure environment variables are actually configured
      if (!validUser || !validPwd) {
        throw new Error('Server configuration missing');
      }

      // Check credentials
      if (user === validUser && pwd === validPwd) {
        // Officially supported Vercel API for continuing the request to static files
        return next();
      }
    } catch (e) {
      // Catch malformed base64, missing headers, or missing env vars.
      // Silently fall through to the 401 response below instead of throwing 500.
    }
  }

  // HTTP 401 for unauthenticated, wrong password, or malformed requests
  return new Response('Accès Refusé - Zone Sécurisée GEOINT', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="Secure Area"'
    }
  });
}
