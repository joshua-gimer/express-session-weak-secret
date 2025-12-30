package burp;

import java.util.Arrays;
import java.util.List;

/**
 * Common Express.js session secrets found in the wild.
 * These are defaults, tutorial examples, and commonly used weak secrets.
 */
public final class CommonSecrets {

    private CommonSecrets() {}

    public static final List<String> SECRETS = Arrays.asList(
        // Express/Node defaults and examples
        "keyboard cat",
        "secret",
        "session secret",
        "session_secret",
        "sessionSecret",
        "express",
        "express-session",
        "my secret",
        "mysecret",
        "my-secret",
        "supersecret",
        "super secret",
        "topsecret",
        "changeme",
        "changeit",
        "password",
        "password123",
        "123456",
        "12345678",
        "abc123",
        "qwerty",
        "admin",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "login",
        "passw0rd",
        "hello",
        "shadow",
        "sunshine",
        "princess",
        "development",
        "dev",
        "test",
        "testing",
        "debug",
        "production",
        "staging",
        "local",
        "localhost",
        "default",
        "demo",
        "example",
        "sample",
        "temp",
        "temporary",
        "xxx",
        "asdf",
        "asdfgh",
        "zxcvbn",
        "1234567890",
        "0987654321",
        "qwertyuiop",
        // Common environment variable patterns
        "SESSION_SECRET",
        "EXPRESS_SECRET",
        "APP_SECRET",
        "COOKIE_SECRET",
        "JWT_SECRET",
        // From tutorials/docs
        "shhhhh",
        "shhhhhhhhhhhhhh",
        "very secret string",
        "this is a secret",
        "replace this with a real secret",
        "your-secret-key",
        "your_secret_key",
        "my-super-secret",
        "some-secret",
        "a]4@TZyeP3Zb"  // Common in old tutorials
    );
}

