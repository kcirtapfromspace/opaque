// The route configuration is the boundary. Never forward a request or serve assets.
export default {
  fetch() {
    return new Response('Not found.\n', {
      status: 404,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Robots-Tag': 'noindex, noarchive',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  },
};
