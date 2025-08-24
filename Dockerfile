# Use the official Bun image as base
FROM oven/bun:1 as base

# Set working directory
WORKDIR /app

# Copy package.json first for better caching
COPY package.json ./


# Copy source code
COPY . .

# Create directory for SQLite database
RUN mkdir -p /app/data

# Expose port 3000
EXPOSE 3000

# Set environment variables
ENV NODE_ENV=production

# Create a non-root user for security
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 bunuser

# Change ownership of the app directory to the non-root user
RUN chown -R bunuser:nodejs /app
USER bunuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/ || exit 1

# Start the application
CMD ["bun", "run", "start"]
