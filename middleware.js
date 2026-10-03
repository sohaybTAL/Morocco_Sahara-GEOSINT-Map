export const config = {
  matcher: '/(.*)',
}

export default function middleware(req) {
  const basicAuth = req.headers.get('authorization')

  if (basicAuth) {
    const authValue = basicAuth.split(' ')[1]
    const [user, pwd] = atob(authValue).split(':')

    // VOUS POUVEZ CHANGER LE NOM D'UTILISATEUR ET LE MOT DE PASSE ICI
    if (user === 'admin' && pwd === 'ssGEO25') {
      return new Response(null, {
        headers: { 'x-middleware-next': '1' }
      }) // Autoriser l'accès
    }
  }

  // Bloquer l'accès et afficher la fenêtre de connexion
  return new Response('Accès Refusé - Zone Sécurisée', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="Secure Area"'
    }
  })
}
