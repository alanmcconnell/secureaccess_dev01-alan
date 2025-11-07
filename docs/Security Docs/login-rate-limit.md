## Loging Rate Limit

The rate limit code is located in two backend files:

1. Rate Limit Middleware Definition:
server\s01_server-first-api\middleware\auth.js

2. Rate Limit Implementation:
server\s01_server-first-api\routes\auth.js

Here are the specific locations:

In middleware\auth.js:

Lines 90-110: createRateLimiter() function

Lines 112-115: Pre-configured rate limiters:

generalRateLimit - 100 requests per 15 minutes

authRateLimit - 20 auth requests per 15 minutes

passwordResetRateLimit - 3 password reset requests per 15 minutes

In routes\auth.js:

Line 15: strictAuthRateLimit - 5 login attempts per 15 minutes

Line 18: router.use(authRateLimit) - applies to all auth routes

Line 21: router.post('/login', strictAuthRateLimit, login) - applies to login endpoint

The rate limiting uses the express-rate-limit package and tracks requests by IP address with configurable time windows and request limits.