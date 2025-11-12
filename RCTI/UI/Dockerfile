# STIX 2.1 Drag and Drop Modeler UI Dockerfile
# Simple approach: Use pre-built files
FROM nginx:alpine

# Copy pre-built assets directly (build outside Docker first)
COPY app/build /usr/share/nginx/html

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S stixuser -u 1001 && \
    chown -R stixuser:nodejs /usr/share/nginx/html

# Expose port 3000 (different from frontend to avoid conflicts)
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1

CMD ["nginx", "-g", "daemon off;"]