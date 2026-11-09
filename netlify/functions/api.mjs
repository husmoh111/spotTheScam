import { handler } from '../../netlify-api.mjs';
export default async function(request) {
  const headers = Object.fromEntries(request.headers.entries());
  const result = await handler({path:new URL(request.url).pathname,httpMethod:request.method,headers,body:request.method === 'GET' ? '' : await request.text()});
  return new Response(result.body, {status:result.statusCode,headers:result.headers});
}
export const config = {path: '/api/*'};
