import jwt from "jsonwebtoken";

export const protect = (req, res, next) => {
    console.log('=== PROTECT MIDDLEWARE DEBUG ===');
    console.log('Request path:', req.path);
    console.log('Authorization header:', req.headers.authorization || 'NOT PRESENT');

    const authHeader = req.headers.authorization;

    if (!authHeader) {
        console.error('No authorization header found');
        return res.status(401).json({ message: "No authorization header, authorization denied" });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
        console.error('No token found in authorization header');
        return res.status(401).json({ message: "No token provided, authorization denied" });
    }

    console.log('Token extracted:', token.substring(0, 20) + '...');
    console.log('JWT_SECRET available:', process.env.JWT_SECRET ? 'YES' : 'NO');

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Token verified successfully for user:', decoded.user?.username || 'unknown');
        req.user = decoded.user;
        next();
    } catch (err) {
        console.error('Token verification failed:', {
            message: err.message,
            name: err.name,
            expired: err.name === 'TokenExpiredError',
            secret: process.env.JWT_SECRET ? 'PRESENT' : 'MISSING'
        });
        res.status(401).json({
            message: "Token is not valid",
            error: err.message,
            ...(process.env.NODE_ENV === 'development' && {
                debug: {
                    tokenPrefix: token.substring(0, 10) + '...',
                    secretLength: process.env.JWT_SECRET?.length || 0
                }
            })
        });
    }
};
