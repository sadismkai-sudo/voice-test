const SESSION_TEXT = "audio-novel-session-v1";

async function createSessionToken(secret) {
    const encoder = new TextEncoder();

    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(secret),
        {
            name: "HMAC",
            hash: "SHA-256"
        },
        false,
        ["sign"]
    );

    const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        encoder.encode(SESSION_TEXT)
    );

    return btoa(
        String.fromCharCode(...new Uint8Array(signature))
    );
}

async function isValidSession(request, secret) {
    const cookie = request.headers.get("Cookie") || "";
    const match = cookie.match(/audio_novel_session=([^;]+)/);

    if (!match) {
        return false;
    }

    const expectedToken = await createSessionToken(secret);

    return match[1] === expectedToken;
}

function loginPage(error = "") {
    return `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Audio Novel</title>
<style>
body {
    margin: 0;
    background: #111;
    color: #eee;
    font-family: serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}
.box {
    width: min(90%, 400px);
    text-align: center;
}
input {
    box-sizing: border-box;
    width: 100%;
    padding: 14px;
    margin: 15px 0;
    background: #222;
    color: #fff;
    border: 1px solid #555;
    border-radius: 4px;
    font-size: 16px;
}
button {
    padding: 12px 28px;
    background: #eee;
    color: #111;
    border: 0;
    border-radius: 4px;
    font-size: 16px;
}
.error {
    color: #d88;
}
</style>
</head>
<body>
<div class="box">
    <h1>Audio Novel</h1>
    <p>アクセスキーを入力してください。</p>

    ${error ? `<p class="error">${error}</p>` : ""}

    <form method="POST" action="/login">
        <input
            type="password"
            name="key"
            placeholder="アクセスキー"
            autocomplete="off"
            required
        >
        <br>
        <button type="submit">入場する</button>
    </form>
</div>
</body>
</html>`;
}

export async function onRequest(context) {
    const { request, env, next } = context;
    const url = new URL(request.url);

    const secret = String(env.ACCESS_KEY || "")
    .normalize("NFKC")
    .replace(/[\s\u200B-\u200D\uFEFF]/g, "");

    if (!secret) {
        return new Response(
            "ACCESS_KEY is not configured.",
            { status: 500 }
        );
    }

    // ログイン処理
    if (url.pathname === "/login" && request.method === "POST") {
        const formData = await request.formData();
       const enteredKey = String(formData.get("key") || "").replace(/[\s\u200B-\u200D\uFEFF]/g, "");

        if (enteredKey !== secret) {
            return new Response(
                loginPage("アクセスキーが正しくありません。"),
                {
                    status: 401,
                    headers: {
                        "Content-Type": "text/html; charset=UTF-8"
                    }
                }
            );
        }

        const token = await createSessionToken(secret);

        return new Response(null, {
            status: 302,
            headers: {
                "Location": "/",
                "Set-Cookie":
                    `audio_novel_session=${token}; ` +
                    `Path=/; ` +
                    `HttpOnly; ` +
                    `Secure; ` +
                    `SameSite=Lax; ` +
                    `Max-Age=2592000`
            }
        });
    }

    // ログイン画面
    if (url.pathname === "/login") {
        return new Response(loginPage(), {
            headers: {
                "Content-Type": "text/html; charset=UTF-8"
            }
        });
    }

    // 認証済みなら、そのまま本来のページへ
    if (await isValidSession(request, secret)) {
        return next();
    }

    // 未認証ならログイン画面へ
    return Response.redirect(
        new URL("/login", request.url),
        302
    );
}
// access key configuration updated
