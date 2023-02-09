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

### JwtFilter.java

```
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    private final TokenProvider tokenProvider;


    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(7);
        }
        return null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwt = resolveToken(request);

        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }
}
```
**resolveToken()**

- Request Header에서 토큰 정보를 꺼내오는 메서드

**doFilterInternal**

- resolveToken()을 통해 토큰 정보를 꺼내와서 validateToken으로 유효성 검사 후 Authentication 객체로 만들어서 SecurityContextHolder에 넣어준다.

### JwtAuthenticationEntryPoint.java

```
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        // 유효한 자격증명을 제공하지 않고 접근하려 할때 401
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
```
### JwtAccessDeniedHandler.java

```
@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // 필요한 권한이 없이 접근하려 할때 403
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }
}
```

해당 클래스는 예외 핸들링을 위한 클래스이다.

## JwtSecurityConfig

### JwtSecurityConfig.java
```
@RequiredArgsConstructor
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private final TokenProvider tokenProvider;

    @Override
    public void configure(HttpSecurity http) {
        JwtFilter customFilter = new JwtFilter(tokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
```

- SecurityConfigurerAdapter 구현체로써, 내가 만든 클래스를 사용하기 위해 적용하는 Configuration 클래스이다.
- TokenProvider를 중비받아서 JwtFilter를 통해 SecurityConfig안에 필터를 등록시킨다.

## WebSecurityConfig

### WebSecurityConfig.java
```
@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@Component
public class WebSecurityConfig {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                .and().authorizeHttpRequests()
                .requestMatchers("/auth/**").permitAll()
                .anyRequest().authenticated()

                .and()
                .apply(new JwtSecurityConfig(tokenProvider));

        return http.build();
    }
}
```

- passwordEncoder(): request로 받은 비밀번호를 암호화해서 DB에 저장하기 위한 메서드
- .exceptionHandling()
  .authenticationEntryPoint(jwtAuthenticationEntryPoint)
  .accessDeniedHandler(jwtAccessDeniedHandler)
  
  예외를 처리하기 위해 넣었다.
  
## SecurityUtil

### SecurityUtil

```
public class SecurityUtil {

    private SecurityUtil() { }

    public static Long getCurrentMemberId() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication.getName() == null) {
            throw new RuntimeException("Security Context에 인증 정보가 없습니다.");
        }

        return Long.parseLong(authentication.getName());
    }
}
```

## Service

### CustomUserDetailsService
```
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return memberRepository.findByEmail(username)
                .map(this::createUserDetails)
                .orElseThrow(() -> new UsernameNotFoundException(username + " 을 DB에서 찾을 수 없습니다"));
    }

    private UserDetails createUserDetails(Member member) {
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(member.getAuthority().toString());

        return new User(
                String.valueOf(member.getId()),
                member.getPassword(),
                Collections.singleton(grantedAuthority)
        );
    }
}
```
- loadUserByUsername(): 요청으로 받은 email로 user가 실제 존재하는지를 확인하는 메서드, 존재하지 않으면 예외 반환

### AuthService

```
@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {
    private final AuthenticationManagerBuilder managerBuilder;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;

    public MemberResponseDto signup(MemberRequestDto requestDto) {
        if (memberRepository.existsByEmail(requestDto.getEmail())) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다");
        }

        Member member = requestDto.toMember(passwordEncoder);
        return MemberResponseDto.of(memberRepository.save(member));
    }

    public TokenDto login(MemberRequestDto requestDto) {
        UsernamePasswordAuthenticationToken authenticationToken = requestDto.toAuthentication();

        Authentication authentication = managerBuilder.getObject().authenticate(authenticationToken);

        return tokenProvider.generateTokenDto(authentication);
    }

}
```
- signup(): DB에 이메일로 조회해서 값이 True이면 런타임 에러를 반환하며, 처음일 경우 MemberResponseDto를 생성하여 반환한다.

## 구현

### 회원가입

![image](https://user-images.githubusercontent.com/93868431/217818402-783c79bd-441c-4792-9533-54f7a1250b01.png)

### 로그인

![image](https://user-images.githubusercontent.com/93868431/217818454-900d85e9-df7b-4c46-9cd1-286a7cae6630.png)

### 유저 정보

![image](https://user-images.githubusercontent.com/93868431/217818485-e84e8836-c4c3-4f4f-9a39-68cc7514b863.png)


