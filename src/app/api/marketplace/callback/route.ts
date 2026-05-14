import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
    const isHttps = req.nextUrl.protocol === "https:";
    const cookiePrefix = isHttps ? "__Host-" : "";
    
    const stateCookie = req.cookies.get(`${cookiePrefix}pkce_state`)?.value;
    const verifierCookie = req.cookies.get(`${cookiePrefix}pkce_verifier`)?.value;
    const urlState = req.nextUrl.searchParams.get("state");
    
    if (!stateCookie || urlState !== stateCookie) {
        return NextResponse.json({ error: "State mismatch" }, { status: 400 });
    }
    
    if (!verifierCookie) {
        return NextResponse.json({ error: "Missing code_verifier" }, { status: 400 });
    }
    
    const res = NextResponse.redirect(new URL("/", req.nextUrl.origin), 302);
    
    res.cookies.set(`${cookiePrefix}pkce_state`, "", {
        httpOnly: true,
        secure: isHttps,
        sameSite: "lax",
        path: "/api/marketplace/callback",
        maxAge: 0
    });
    
    res.cookies.set(`${cookiePrefix}pkce_verifier`, "", {
        httpOnly: true,
        secure: isHttps,
        sameSite: "lax",
        path: "/api/marketplace/callback",
        maxAge: 0
    });
    
    return res;
}
