/**
 * MCP Server with GitHub OAuth for Claude.ai Custom Integrations
 */

export interface Env {
  OAUTH_KV: KVNamespace;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  COOKIE_ENCRYPTION_KEY: string;
  ALLOWED_USERNAMES?: string;
}

interface GitHubUser {
  id: number;
  login: string;
  name: string | null;
  email: string | null;
  avatar_url: string;
}

interface AuthContext {
  userId: string;
  username: string;
  name?: string;
  email?: string;
  avatarUrl?: string;
  accessToken: string;
}

interface MCPRequest {
  jsonrpc: string;
  method: string;
  params?: any;
  id?: string | number;
}

interface MCPResponse {
  jsonrpc: string;
  result?: any;
  error?: any;
  id?: string | number;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    
    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    // Health check
    if (url.pathname === '/health') {
      return new Response('OK', { headers: corsHeaders });
    }
    
    // OAuth metadata discovery
    if (url.pathname === '/.well-known/oauth-authorization-server') {
      return handleOAuthMetadata(request, env);
    }
    
    // OAuth 2.0 Protected Resource Metadata (RFC 9728)
    if (url.pathname === '/.well-known/oauth-protected-resource') {
      return handleProtectedResourceMetadata(request, env);
    }
    
    // Dynamic client registration
    if (url.pathname === '/register') {
      return handleClientRegistration(request, env);
    }
    
    // GitHub OAuth flow
    if (url.pathname === '/auth' || url.pathname === '/') {
      return handleAuth(request, env);
    }
    
    if (url.pathname === '/callback') {
      return handleCallback(request, env);
    }
    
    if (url.pathname === '/token') {
      return handleToken(request, env);
    }
    
    // SSE endpoint for MCP clients
    if (url.pathname === '/sse') {
      return handleSSE(request, env);
    }
    
    // HTTP POST endpoint for MCP（Streamable HTTP）
    if (url.pathname === '/mcp') {
      return handleMCP(request, env, corsHeaders);
    }
    
    return new Response('Not Found', { status: 404, headers: corsHeaders });
  }
};

async function handleOAuthMetadata(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const baseUrl = url.origin;
  
  const metadata = {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/auth`,
    token_endpoint: `${baseUrl}/token`,
    registration_endpoint: `${baseUrl}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['read:user', 'user:email'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    client_registration_types_supported: ['dynamic']
  };
  
  return new Response(JSON.stringify(metadata), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

async function handleProtectedResourceMetadata(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const baseUrl = url.origin;
  
  const metadata = {
    // Required parameter: The protected resource's resource identifier
    resource: `${baseUrl}/mcp`,
    
    // Optional: Authorization servers that can be used with this protected resource
    authorization_servers: [
      baseUrl // This server acts as both authorization server and protected resource
    ],
    
    // Optional: Scopes supported by this protected resource
    scopes_supported: [
      'read:user',
      'user:email'
    ],
    
    // Optional: Bearer token presentation methods supported
    bearer_methods_supported: [
      'header', // Authorization: Bearer <token>
      'query'   // ?token=<token>
    ],
    
    // Optional: Additional metadata about the protected resource
    resource_documentation: 'https://github.com/cloudflare/workers-oauth-provider',
    resource_policy_uri: `${baseUrl}/terms`,
    resource_tos_uri: `${baseUrl}/terms`,
    
    // MCP-specific metadata
    mcp_version: '2024-11-05',
    mcp_endpoints: {
      sse: `${baseUrl}/sse`,
      http: `${baseUrl}/mcp`
    }
  };
  
  return new Response(JSON.stringify(metadata), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=3600' // Cache for 1 hour
    }
  });
}

async function handleClientRegistration(request: Request, env: Env): Promise<Response> {
  try {
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({
        error: 'invalid_request',
        error_description: 'Only POST method is supported'
      }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const registrationRequest = await request.json() as any;
    
    // Generate client credentials
    const clientId = crypto.randomUUID();
    const clientSecret = crypto.randomUUID();
    
    // Store client information
    const clientInfo = {
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: registrationRequest.redirect_uris || [],
      grant_types: registrationRequest.grant_types || ['authorization_code'],
      response_types: registrationRequest.response_types || ['code'],
      scope: registrationRequest.scope || 'read:user user:email',
      client_name: registrationRequest.client_name || 'MCP Client',
      created_at: Date.now()
    };
    
    // Store in KV with TTL (30 days)
    await env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(clientInfo), { 
      expirationTtl: 30 * 24 * 60 * 60 
    });
    
    // Return client registration response
    const response = {
      client_id: clientId,
      client_secret: clientSecret,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_secret_expires_at: 0, // Never expires
      redirect_uris: clientInfo.redirect_uris,
      grant_types: clientInfo.grant_types,
      response_types: clientInfo.response_types,
      scope: clientInfo.scope,
      client_name: clientInfo.client_name
    };
    
    return new Response(JSON.stringify(response), {
      status: 201,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      }
    });
    
  } catch (error) {
    console.error('Client registration error:', error);
    return new Response(JSON.stringify({
      error: 'server_error',
      error_description: 'Internal server error during client registration'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleAuth(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const state = url.searchParams.get('state') || crypto.randomUUID();
  const redirectUri = url.searchParams.get('redirect_uri');
  const clientId = url.searchParams.get('client_id');
  
  // Validate client if client_id is provided
  if (clientId) {
    const clientData = await env.OAUTH_KV.get(`client:${clientId}`);
    if (!clientData) {
      return new Response('Invalid client_id', { status: 400 });
    }
    
    const clientInfo = JSON.parse(clientData);
    // Validate redirect_uri if client has registered redirect_uris
    if (clientInfo.redirect_uris.length > 0 && redirectUri && !clientInfo.redirect_uris.includes(redirectUri)) {
      return new Response('Invalid redirect_uri', { status: 400 });
    }
  }
  
  // Store state and redirect_uri in KV for verification
  const stateData = {
    timestamp: Date.now(),
    redirect_uri: redirectUri,
    client_id: clientId
  };
  await env.OAUTH_KV.put(`state:${state}`, JSON.stringify(stateData), { expirationTtl: 600 });
  
  const callbackUri = `${url.origin}/callback`;
  console.log('Callback URI:', callbackUri);
  
  const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
  githubAuthUrl.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
  githubAuthUrl.searchParams.set('redirect_uri', callbackUri);
  githubAuthUrl.searchParams.set('scope', 'read:user user:email');
  githubAuthUrl.searchParams.set('state', state);
  
  return Response.redirect(githubAuthUrl.toString(), 302);
}

async function handleCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  
  if (!code || !state) {
    return new Response('Missing code or state', { status: 400 });
  }
  
  // Verify state
  const storedStateData = await env.OAUTH_KV.get(`state:${state}`);
  if (!storedStateData) {
    return new Response('Invalid state', { status: 400 });
  }
  
  const stateData = JSON.parse(storedStateData);
  
  try {
    // Exchange code for access token
    console.log('Exchanging code for token with GitHub...');
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code: code,
      }),
    });
    
    console.log('GitHub token response status:', tokenResponse.status);
    
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('GitHub token error:', errorText);
      throw new Error(`Failed to exchange code for token: ${errorText}`);
    }
    
    const tokenData = await tokenResponse.json() as any;
    console.log('GitHub token data:', tokenData);
    const accessToken = tokenData.access_token;
    
    if (!accessToken) {
      console.error('No access token in response:', tokenData);
      throw new Error(`No access token received: ${JSON.stringify(tokenData)}`);
    }
    
    // Get user info
    console.log('Fetching user info from GitHub API...');
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'MCP-GitHub-OAuth-Demo/1.0.0',
      },
    });
    
    console.log('GitHub user response status:', userResponse.status);
    
    if (!userResponse.ok) {
      const errorText = await userResponse.text();
      console.error('GitHub user API error:', errorText);
      throw new Error(`Failed to get user info: ${userResponse.status} ${errorText}`);
    }
    
    const userData = await userResponse.json() as GitHubUser;
    console.log('GitHub user data:', userData);
    
    // Check if user is allowed (if ALLOWED_USERNAMES is set)
    if (env.ALLOWED_USERNAMES) {
      const allowedUsers = env.ALLOWED_USERNAMES.split(',').map(u => u.trim());
      if (!allowedUsers.includes(userData.login)) {
        return new Response('Access denied', { status: 403 });
      }
    }
    
    // Store auth context
    const authContext: AuthContext = {
      userId: userData.id.toString(),
      username: userData.login,
      name: userData.name || undefined,
      email: userData.email || undefined,
      avatarUrl: userData.avatar_url,
      accessToken: accessToken,
    };
    
    // Generate authorization code and session ID
    const authCode = crypto.randomUUID();
    const sessionId = crypto.randomUUID();
    
    // Store the session data (longer TTL)
    await env.OAUTH_KV.put(`session:${sessionId}`, JSON.stringify(authContext), { 
      expirationTtl: 3600 // 1 hour
    });
    
    // Store the authorization code with metadata (shorter TTL)
    const authCodeInfo = {
      session_id: sessionId,
      client_id: stateData.client_id,
      redirect_uri: stateData.redirect_uri,
      created_at: Date.now(),
      used: false
    };
    await env.OAUTH_KV.put(`authcode:${authCode}`, JSON.stringify(authCodeInfo), { 
      expirationTtl: 600 // 10 minutes
    });
    
    // Get the original redirect_uri from the stored state data
    const redirectUri = stateData.redirect_uri || 'urn:ietf:wg:oauth:2.0:oob';
    
    // Clean up state data
    await env.OAUTH_KV.delete(`state:${state}`);
    
    // Redirect back to the client with the authorization code
    if (redirectUri === 'urn:ietf:wg:oauth:2.0:oob') {
      // Out-of-band flow - show the code to the user
      return new Response(`
        <html>
          <head><title>Authorization Code</title></head>
          <body>
            <h1>認証が完了しました！</h1>
            <p>ユーザー: ${userData.login}</p>
            <p>認証コード: <code>${authCode}</code></p>
            <p>このコードを使用してアクセストークンを取得してください。</p>
          </body>
        </html>
      `, {
        headers: { 'Content-Type': 'text/html' },
      });
    } else {
      // Standard redirect flow
      const callbackUrl = new URL(redirectUri);
      callbackUrl.searchParams.set('code', authCode);
      callbackUrl.searchParams.set('state', state);
      
      return Response.redirect(callbackUrl.toString(), 302);
    }
    
  } catch (error) {
    console.error('OAuth callback error:', error);
    return new Response(`Authentication failed: ${error}`, { status: 500 });
  }
}

async function handleToken(request: Request, env: Env): Promise<Response> {
  try {
    console.log('Token endpoint called');
    console.log('Request method:', request.method);
    console.log('Content-Type:', request.headers.get('content-type'));
    
    let body: any;
    
    // Handle both form data and JSON
    const contentType = request.headers.get('content-type') || '';
    
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = {
        grant_type: formData.get('grant_type'),
        code: formData.get('code'),
        redirect_uri: formData.get('redirect_uri'),
        client_id: formData.get('client_id'),
        client_secret: formData.get('client_secret'),
        code_verifier: formData.get('code_verifier'),
      };
    } else {
      body = await request.json();
    }
    
    console.log('Token request body:', body);
    
    const { grant_type, code, redirect_uri, client_id, client_secret } = body;
    
    if (grant_type !== 'authorization_code') {
      return new Response(JSON.stringify({
        error: 'unsupported_grant_type',
        error_description: 'Only authorization_code grant type is supported'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Validate client credentials if provided
    if (client_id) {
      const clientData = await env.OAUTH_KV.get(`client:${client_id}`);
      if (!clientData) {
        return new Response(JSON.stringify({
          error: 'invalid_client',
          error_description: 'Invalid client_id'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const clientInfo = JSON.parse(clientData);
      // Verify client_secret if the client has one
      if (clientInfo.client_secret && client_secret !== clientInfo.client_secret) {
        return new Response(JSON.stringify({
          error: 'invalid_client',
          error_description: 'Invalid client_secret'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
    
    if (!code) {
      return new Response(JSON.stringify({
        error: 'invalid_request',
        error_description: 'Missing authorization code'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Validate the authorization code
    console.log('Validating authorization code:', code);
    const authCodeData = await env.OAUTH_KV.get(`authcode:${code}`);
    if (!authCodeData) {
      console.error('Authorization code not found:', code);
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const authCodeInfo = JSON.parse(authCodeData);
    console.log('Authorization code info:', authCodeInfo);
    
    // Check if the authorization code has expired (10 minutes)
    const now = Date.now();
    const codeAge = now - authCodeInfo.created_at;
    const maxAge = 10 * 60 * 1000; // 10 minutes
    
    if (codeAge > maxAge) {
      console.error('Authorization code expired');
      await env.OAUTH_KV.delete(`authcode:${code}`);
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Authorization code has expired'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Validate redirect_uri if provided
    if (redirect_uri && authCodeInfo.redirect_uri !== redirect_uri) {
      console.error('Redirect URI mismatch');
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Redirect URI mismatch'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Validate client_id if the code was issued to a specific client
    if (authCodeInfo.client_id && client_id !== authCodeInfo.client_id) {
      console.error('Client ID mismatch');
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Authorization code was not issued to this client'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Get the session data associated with this authorization code
    const sessionData = await env.OAUTH_KV.get(`session:${authCodeInfo.session_id}`);
    if (!sessionData) {
      console.error('Session not found for authorization code');
      await env.OAUTH_KV.delete(`authcode:${code}`);
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Session not found'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const authContext: AuthContext = JSON.parse(sessionData);
    
    // Generate a new access token (different from the authorization code)
    const accessToken = crypto.randomUUID();
    
    // Store the access token with the session information
    await env.OAUTH_KV.put(`access_token:${accessToken}`, JSON.stringify(authContext), { 
      expirationTtl: 3600 // 1 hour
    });
    
    // Delete the authorization code (one-time use)
    await env.OAUTH_KV.delete(`authcode:${code}`);
    
    console.log('Token issued successfully');
    
    return new Response(JSON.stringify({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'read:user user:email'
    }), {
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }
    });
    
  } catch (error) {
    console.error('Token endpoint error:', error);
    return new Response(JSON.stringify({
      error: 'server_error',
      error_description: 'Internal server error'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleSSE(request: Request, env: Env): Promise<Response> {
  // Extract access token from Authorization header or query params
  let accessToken: string | null = null;
  
  const authHeader = request.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    accessToken = authHeader.substring(7);
  } else {
    const url = new URL(request.url);
    accessToken = url.searchParams.get('token');
  }
  
  if (!accessToken) {
    return new Response('Unauthorized', { status: 401 });
  }
  
  // Get auth context
  const authData = await env.OAUTH_KV.get(`access_token:${accessToken}`);
  if (!authData) {
    return new Response('Invalid or expired access token', { status: 401 });
  }
  
  const authContext: AuthContext = JSON.parse(authData);
  
  // Create SSE response
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();
  
  // Send initial connection message
  await writer.write(encoder.encode('data: {"type":"connection","message":"Connected to MCP server"}\n\n'));
  
  // Keep connection alive
  const keepAlive = setInterval(async () => {
    try {
      await writer.write(encoder.encode('data: {"type":"ping"}\n\n'));
    } catch {
      clearInterval(keepAlive);
    }
  }, 30000);
  
  return new Response(readable, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

async function handleMCP(request: Request, env: Env, corsHeaders: Record<string, string>): Promise<Response> {
  try {
    // Extract session from Authorization header
    const authHeader = request.headers.get('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return new Response(JSON.stringify({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Authentication required' }
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    const accessToken = authHeader.substring(7);
    const authData = await env.OAUTH_KV.get(`access_token:${accessToken}`);
    if (!authData) {
      return new Response(JSON.stringify({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Invalid or expired access token' }
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    const authContext: AuthContext = JSON.parse(authData);
    
    // Process MCP request
    const mcpRequest: MCPRequest = await request.json();
    const response = await processMCPRequest(mcpRequest, authContext, env);
    
    return new Response(JSON.stringify(response), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
    
  } catch (error) {
    console.error('MCP error:', error);
    return new Response(JSON.stringify({
      jsonrpc: '2.0',
      error: { code: -32603, message: 'Internal error' }
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

async function processMCPRequest(request: MCPRequest, authContext: AuthContext, env: Env): Promise<MCPResponse> {
  const { method, params, id } = request;
  
  try {
    let result: any;
    
    switch (method) {
      case 'initialize':
        result = {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: {},
            resources: {},
          },
          serverInfo: {
            name: 'mcp-github-oauth-demo',
            version: '1.0.0',
          },
        };
        break;
        
      case 'tools/list':
        result = {
          tools: [
            {
              name: 'get_user_info',
              description: '認証されたユーザーの情報を取得',
              inputSchema: {
                type: 'object',
                properties: {},
              },
            },
            {
              name: 'calculate',
              description: '数値計算を実行',
              inputSchema: {
                type: 'object',
                properties: {
                  operation: {
                    type: 'string',
                    enum: ['add', 'subtract', 'multiply', 'divide'],
                    description: '実行する演算',
                  },
                  a: { type: 'number', description: '第1オペランド' },
                  b: { type: 'number', description: '第2オペランド' },
                },
                required: ['operation', 'a', 'b'],
              },
            },
            {
              name: 'get_github_repos',
              description: 'GitHubリポジトリ一覧を取得',
              inputSchema: {
                type: 'object',
                properties: {
                  limit: {
                    type: 'number',
                    description: '取得する最大数',
                    default: 10,
                  },
                },
              },
            },
          ],
        };
        break;
        
      case 'tools/call':
        const toolName = params?.name;
        const args = params?.arguments || {};
        
        if (toolName === 'get_user_info') {
          result = {
            content: [{
              type: 'text',
              text: `ユーザー情報:\n- ユーザー名: ${authContext.username}\n- 名前: ${authContext.name || '未設定'}\n- メール: ${authContext.email || '未設定'}`,
            }],
          };
        } else if (toolName === 'calculate') {
          const { operation, a, b } = args;
          let calcResult: number;
          
          switch (operation) {
            case 'add':
              calcResult = a + b;
              break;
            case 'subtract':
              calcResult = a - b;
              break;
            case 'multiply':
              calcResult = a * b;
              break;
            case 'divide':
              if (b === 0) throw new Error('Division by zero');
              calcResult = a / b;
              break;
            default:
              throw new Error(`Unknown operation: ${operation}`);
          }
          
          result = {
            content: [{
              type: 'text',
              text: `計算結果: ${a} ${operation} ${b} = ${calcResult}\n実行ユーザー: ${authContext.username}`,
            }],
          };
        } else if (toolName === 'get_github_repos') {
          const limit = args.limit || 10;
          
          const reposResponse = await fetch(`https://api.github.com/user/repos?per_page=${limit}`, {
            headers: {
              'Authorization': `Bearer ${authContext.accessToken}`,
              'Accept': 'application/vnd.github.v3+json',
              'User-Agent': 'MCP-GitHub-OAuth-Demo/1.0.0',
            },
          });
          
          if (!reposResponse.ok) {
            throw new Error('Failed to fetch repositories');
          }
          
          const repos = await reposResponse.json() as any[];
          const repoList = repos.map(repo => 
            `- ${repo.name}: ${repo.description || '説明なし'} (${repo.private ? 'プライベート' : 'パブリック'})`
          ).join('\n');
          
          result = {
            content: [{
              type: 'text',
              text: `GitHubリポジトリ一覧 (${repos.length}件):\n${repoList}`,
            }],
          };
        } else {
          throw new Error(`Unknown tool: ${toolName}`);
        }
        break;
        
      case 'resources/list':
        result = {
          resources: [
            {
              uri: `github://user/${authContext.username}`,
              name: 'GitHub User Profile',
              description: '認証されたユーザーのGitHubプロフィール',
              mimeType: 'application/json',
            },
          ],
        };
        break;
        
      case 'resources/read':
        const uri = params?.uri;
        if (uri === `github://user/${authContext.username}`) {
          result = {
            contents: [{
              uri: uri,
              mimeType: 'application/json',
              text: JSON.stringify({
                username: authContext.username,
                name: authContext.name,
                email: authContext.email,
                avatarUrl: authContext.avatarUrl,
              }, null, 2),
            }],
          };
        } else {
          throw new Error(`Unknown resource: ${uri}`);
        }
        break;
        
      default:
        throw new Error(`Unknown method: ${method}`);
    }
    
    return { jsonrpc: '2.0', result, id };
    
  } catch (error) {
    return {
      jsonrpc: '2.0',
      error: {
        code: -32603,
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      id,
    };
  }
}