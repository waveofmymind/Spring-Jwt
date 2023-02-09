# Spring Security를 이용한 JWT 로그인 서비스

## JWT

- Json Web Token의 약자로, **인증에 필요한 정보를 암호화시킨 Json 형식의 토큰**

- 클라이언트는 Jwt 토큰을 헤더에 실어 보내고, 이를 받은 서버는 Jwt 토큰을 통해 클라이언트를 식별한다.

- 보통은 Base64 Encode로 Json 데이터를 암호화

## 인증 과정

![image](https://user-images.githubusercontent.com/93868431/217736284-e0258090-26a9-4891-9e18-d60505de3795.png)


## 주요 로직

### TokenProvider.java
```
@Component
@Slf4j
public class TokenProvider {

    private static final String AUTHORITIES_KEY = "auth";
    private static final String BEARER_TYPE = "bearer";
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30;
    private final Key key;



    // 주의점: 여기서 @Value는 `springframework.beans.factory.annotation.Value`소속이다! lombok의 @Value와 착각하지 말것!
    //     * @param secretKey
    public TokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public TokenDto generateTokenDto(Authentication authentication) {

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();


        Date tokenExpiresIn = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);

        System.out.println(tokenExpiresIn);

        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .setExpiration(tokenExpiresIn)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        return TokenDto.builder()
                .grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .tokenExpiresIn(tokenExpiresIn.getTime())
                .build();
    }

    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);

        if (claims.get(AUTHORITIES_KEY) == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        UserDetails principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}
```
- AUTHORITIES_KEY, BEARER_TYPE: 토큰을 생성하고 검증할 때 쓰이는 String 값
- ACCESS_TOKEN_EXPIRE_TIME: 토큰의 만료 시간
- key: JWT를 만들 때 사용하는 암호화 키 값, 생성자를 통해 @Value 어노테이션으로 미리 yml에 넣어놓은 secret key를 decode해서 주입한다.

**genetateTokenDto**

- 토큰을 만드는 메서드
- 토큰의 만료시간, 현재 시각을 생성하여 Jwts의 builder를 이용해 Token을 생성한다.

**getAuthentication**

- 토큰을 받았을 때 인증을 꺼내는 메서드
- parseClaims 메서드로 String 형태의 토큰을 claims 형태로 생성한다.
- token에서 꺼낸 정보를 Spring Security의 UserDetails에 넣고 UsernamePasswordAuthenticationToken 안에 인가와 같이 넣고 반환한다.
- 이 때, UPAT를 만드는 이유는, Spring Security에서는 SecurityContext 내에 Authentication의 객체만 저장될 수 있기 때문이다.

**validateToken**

- 토큰 검증용 메서드

**parseClaims**

- 토큰을 claims 형태로 만드는 메서드



