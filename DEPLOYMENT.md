# Deployment Guide

This guide covers deploying WhoisMCP to various free hosting platforms.

## 🌐 Free Hosting Options Comparison

| Platform | Free Tier | Always-On | SSE Support | Deployment |
|----------|-----------|-----------|-------------|------------|
| **Fly.io** | 3 VMs, 256MB | ✅ Yes | ✅ Yes | `flyctl` |
| **Render** | 750 hrs/mo | ⚠️ Spins down | ✅ Yes | Git push |
| **Railway** | $5/mo credit | ✅ Yes | ✅ Yes | Git push |
| **Google Cloud Run** | 2M requests | ⚠️ Cold starts | ✅ Yes | `gcloud` |

## 1. Fly.io (Recommended)

**Best for:** Always-on MCP server with SSE support

### Setup

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login
flyctl auth login

# Deploy
flyctl launch
flyctl deploy
```

### Get your URL
```bash
flyctl info
# Your app will be at: https://your-app.fly.dev
```

### Configuration

The `fly.toml` file is already configured. You can customize:

```bash
# Set environment variables
flyctl secrets set BULK_CHECK_MAX_DOMAINS=200
flyctl secrets set CACHE_TTL=7200

# Scale (free tier limits)
flyctl scale count 1
flyctl scale memory 256
```

### Usage

After deployment, your MCP server endpoints will be:
- Health: `https://your-app.fly.dev/health`
- MCP Messages: `https://your-app.fly.dev/message`
- SSE: `https://your-app.fly.dev/sse`

---

## 2. Render

**Best for:** Auto-deploys from GitHub

### Setup

1. Push your code to GitHub
2. Go to [render.com](https://render.com)
3. Click "New +" → "Web Service"
4. Connect your GitHub repo
5. Render will detect `render.yaml` automatically
6. Click "Create Web Service"

### Configuration

`render.yaml` is already set up. Customize via Render dashboard:
- Environment variables
- Auto-deploy on git push
- Health check endpoint: `/health`

**Note:** Free tier sleeps after 15 minutes of inactivity. First request may be slow.

---

## 3. Railway

**Best for:** Quick deployments with $5/month free credit

### Setup

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Deploy
railway init
railway up
```

Or use the web interface:
1. Go to [railway.app](https://railway.app)
2. Connect GitHub repo
3. Railway auto-detects Python
4. Set environment variables in dashboard

### Environment Variables

```
TRANSPORT_MODE=sse
BIND_HOST=0.0.0.0
BIND_PORT=$PORT
```

---

## 4. Google Cloud Run

**Best for:** Scalability with generous free tier

### Setup

```bash
# Install gcloud CLI
# https://cloud.google.com/sdk/docs/install

# Login
gcloud auth login

# Set project
gcloud config set project YOUR_PROJECT_ID

# Deploy
gcloud run deploy whoismcp \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8080 \
  --set-env-vars "TRANSPORT_MODE=sse,BIND_PORT=8080"
```

### Get URL
```bash
gcloud run services describe whoismcp --region us-central1 --format 'value(status.url)'
```

---

## 🔧 Testing Your Deployment

After deploying, test the endpoints:

```bash
# Health check
curl https://your-app.fly.dev/health

# List MCP tools
curl -X POST https://your-app.fly.dev/message \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1,"params":{}}'

# Bulk domain check
curl -X POST https://your-app.fly.dev/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"tools/call",
    "id":2,
    "params":{
      "name":"check_domains_bulk",
      "arguments":{
        "domains":["example.com","google.com"]
      }
    }
  }'
```

---

## 🔐 Security Considerations

### For Public Deployments

Since MCP servers on free tiers are publicly accessible, consider:

1. **Rate Limiting** - Already built-in with configurable limits
2. **API Keys** - Add authentication if needed
3. **CORS** - Configure allowed origins via `CORS_ALLOWED_ORIGINS`

Example with stricter CORS:
```bash
flyctl secrets set CORS_ALLOWED_ORIGINS="https://yourdomain.com"
```

---

## 📊 Monitoring

### Fly.io
```bash
# View logs
flyctl logs

# Monitor metrics
flyctl dashboard
```

### Render
- View logs in dashboard
- Monitor uptime and restarts
- Set up alerts

### Railway
```bash
# View logs
railway logs

# Open dashboard
railway open
```

---

## 💰 Cost Estimates

All platforms have generous free tiers sufficient for moderate MCP usage:

- **Fly.io**: Free for 3 small VMs (perfect for this)
- **Render**: 750 hours/month free (enough for 1 always-on service)
- **Railway**: $5 credit/month (depletes with usage)
- **Cloud Run**: 2M requests/month free (more than enough)

For a personal MCP server with moderate use, you'll stay within free limits on any platform.

---

## 🚀 Quick Start

**Fastest deployment (5 minutes):**

```bash
# Clone/navigate to your repo
cd whoismcp

# Install Fly CLI
curl -L https://fly.io/install.sh | sh

# Login
flyctl auth login

# Launch (answer prompts with defaults)
flyctl launch

# Deploy
flyctl deploy

# Get your URL
flyctl info
```

Your MCP server is now live at `https://your-app.fly.dev`! 🎉
