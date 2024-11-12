package sn.foad.pocsecurityjwt.config;

public class JWTConstant {
    public static final String SECRET = "monSecretPass";
    public static final String AUTH_HEADER = "Authorization ";
    public static final String PREFIX = "Bearer ";
    public static final long EXPIRE_ACCESS_TOKEN =300;
    public static final long EXPIRE_REFRESH_TOKEN = 1800;


}
