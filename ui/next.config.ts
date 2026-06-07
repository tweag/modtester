import type { NextConfig } from "next";

const apiUrl = process.env.API_URL || "http://localhost:4001";

const nextConfig: NextConfig = {
  output: "standalone",
  async rewrites() {
    return {
      beforeFiles: [],
      afterFiles: [
        // IMPORTANT: AI chat has a route handler - do NOT rewrite it
        // The route handler reads API_URL at runtime for proper ECS deployment
        // Only rewrite other API paths that don't have route handlers
        {
          source: "/api/auth/:path*",
          destination: `${apiUrl}/api/auth/:path*`,
        },
        {
          source: "/api/assessments/:id/chat",
          destination: `${apiUrl}/api/assessments/:id/chat`,
        },
        {
          source: "/api/assessments/:id/reports/:path*",
          destination: `${apiUrl}/api/assessments/:id/reports/:path*`,
        },
        {
          source: "/api/assessments",
          destination: `${apiUrl}/api/assessments`,
        },
        {
          source: "/api/assessments/:id",
          destination: `${apiUrl}/api/assessments/:id`,
        },
      ],
      fallback: [],
    };
  },
};

export default nextConfig;