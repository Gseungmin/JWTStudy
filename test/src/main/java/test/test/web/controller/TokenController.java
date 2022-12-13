package test.test.web.controller;


//@RestController
//@RequiredArgsConstructor
//public class a {
//
////    private final MemberService memberService;
//    private final MemberRepository memberRepository;
//    private final MemberService memberService;
//
//    @PostMapping("/token")
//    public String getToken(HttpServletRequest request) {
//
//        String idToken = request.getHeader("Authorization");
//
////        String username = jwtUtil.getUsernameFromToken(idToken);
////
////        System.out.println("idToken = " + idToken);
////        System.out.println("username = " + username);
//        return "1";
//    }
//
//    @PostMapping("/accessToken")
//    public String getAccessToken(@RequestBody AccessTokenDto accessToken) {
//
//        System.out.println("accessToken = " + accessToken.getAccessToken());
//        return "2";
//    }
//
//    @PostMapping("/login")
//    public MemberDto login(@RequestBody MemberDto memberDto) {
//
//        System.out.println("memberDto = " + memberDto.getEmail());
//
//        return memberDto;
//    }
//
//    @PostMapping("/google")
//    public String google(HttpServletRequest request) {
//
//        String authorization = request.getHeader("Authorization");
//
//        String token = authorization.substring(7);
//        System.out.println("token = " + token);
//
//        String[] chunks = token.split("\\.");
//        System.out.println("chunks = " + chunks);
//
//        Base64.Decoder decoder = Base64.getUrlDecoder();
//
//        String header = new String(decoder.decode(chunks[0]));
//        String payload = new String(decoder.decode(chunks[1]));
//
//        String email = "";
//
//        List<String> info = List.of(payload.split(","));
//        for (String each : info) {
//            if (each.startsWith("\"email\"")) {
//                email = each.substring(9, each.length()-1);
//            }
//        };
//
////        JwtTokenDto tokenInfo = memberService.login(email, "1234");
//
//        System.out.println("header = " + header);
//        System.out.println("payload = " + payload);
////        System.out.println("payload = " + tokenInfo);
//
//        return "1";
//    }
//
//
//    @PostMapping("/kakao")
//    public String kakao(HttpServletRequest request) {
//
//        String authorization = request.getHeader("Authorization");
//
//        String token = authorization.substring(7);
//        System.out.println("token = " + token);
//
//        String[] chunks = token.split("\\.");
//        System.out.println("chunks = " + chunks);
//
//        Base64.Decoder decoder = Base64.getUrlDecoder();
//
//        String header = new String(decoder.decode(chunks[0]));
//        String payload = new String(decoder.decode(chunks[1]));
//
//        System.out.println("header = " + header);
//        System.out.println("payload = " + payload);
//
//        return "1";
//    }
//
//    @PostMapping("/test")
//    public String test(@RequestBody MemberLoginRequestDto memberLoginRequestDto) {
//        String memberId = memberLoginRequestDto.getMemberId();
//        String password = memberLoginRequestDto.getPassword();
//        System.out.println("password = " + password);
////        JwtTokenDto tokenInfo = memberService.login(memberId, password);
////        return tokenInfo;
//        return "1234";
//    }
//
//    @GetMapping("/")
//    public String index() {
//        return "1234";
//    }
//
//    @GetMapping("/testToken")
//    public Authentication testToken(Authentication authentication, @AuthenticationPrincipal Jwt principle) {
//        System.out.println("authentication = " + authentication);
//        System.out.println("authentication = " + authentication.getPrincipal());
//        System.out.println("authentication = " + authentication.getName());
//        System.out.println("authentication = " + authentication.getDetails());
//        System.out.println("authentication = " + authentication.getAuthorities());
//
//        JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) authentication;
//        String sub = (String) authenticationToken.getTokenAttributes().get("sub");
//        String email = (String) authenticationToken.getTokenAttributes().get("email");
//        String scope = (String) authenticationToken.getTokenAttributes().get("scope");
//
//        String sub1 = principle.getClaimAsString("sub");
//        String tokenValue = principle.getTokenValue();
//
//        System.out.println("sub = " + sub);
//        System.out.println("email = " + email);
//        System.out.println("scope = " + scope);
//        System.out.println("sub1 = " + sub1);
//        System.out.println("tokenValue = " + tokenValue);
//        return authentication;
//    }
//
//    @PostMapping("/kakaoLogin")
//    public String kakaoLogin(@PathParam(value = "accessToken") String accessToken) {
//        String reqURL = "https://kapi.kakao.com/v2/user/me";
//
//        System.out.println("accessToken = " + accessToken);
//
//        try {
//            URL url = new URL(reqURL);
//            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
//
//            conn.setRequestMethod("POST");
//            conn.setDoOutput(true);
//            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
//
//            BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
//            String line = "";
//            String result = "";
//
//            while ((line = br.readLine()) != null) {
//                result += line;
//            }
//            System.out.println("response body : " + result);
//
//            JsonElement element = JsonParser.parseString(result);
//
//            String id = element.getAsJsonObject().get("kakao_account").getAsJsonObject().get("email").getAsString();
//            String pwd = element.getAsJsonObject().get("id").getAsString();
//            String nick = element.getAsJsonObject().get("kakao_account").getAsJsonObject().get("profile").getAsJsonObject().get("nickname").getAsString();
//
//            System.out.println("id = " + id);
//            System.out.println("pwd = " + pwd);
//            System.out.println("nick = " + nick);
////            PostUserReq kakaoUserReq = new PostUserReq(id,nick,pwd, "kakao",accessToken);
////            if (userProvider.checkIdExist(id) != 1) {
////                PostUserRes kakaoUserRes = userService.createUser(kakaoUserReq);
////
////                if(kakaoUserRes != null){
////                    String message = "회원가입에 성공하였습니다.";
////                }
////            }
////            PostLoginReq kakaoLoginReq = new PostLoginReq(id,pwd);
////            PostLoginRes kakaoLoinRes = authService.login(kakaoLoginReq);
//
//            br.close();
//            return result;
//        } catch (IOException exception) {
//            exception.printStackTrace();
//        }
//        return "4321";
//    }
//
//
//    @PostMapping("/googleLogin")
//    public String googleLogin(@PathParam(value = "authorizationCode") String authorizationCode) {
//        String reqURL = "https://oauth2.googleapis.com/token";
//
//        System.out.println("AuthorizationCode = " + authorizationCode);
//        return authorizationCode;
////        try {
////            URL url = new URL(reqURL);
////            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
////
////            conn.setRequestMethod("POST");
////            conn.setDoOutput(true);
////            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
////
////            BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
////            String line = "";
////            String result = "";
////
////            while ((line = br.readLine()) != null) {
////                result += line;
////            }
////            System.out.println("response body : " + result);
////
////            JsonElement element = JsonParser.parseString(result);
////
////            System.out.println("element = " + element);
////
//////            PostUserReq kakaoUserReq = new PostUserReq(id,nick,pwd, "kakao",accessToken);
//////            if (userProvider.checkIdExist(id) != 1) {
//////                PostUserRes kakaoUserRes = userService.createUser(kakaoUserReq);
//////
//////                if(kakaoUserRes != null){
//////                    String message = "회원가입에 성공하였습니다.";
//////                }
//////            }
//////            PostLoginReq kakaoLoginReq = new PostLoginReq(id,pwd);
//////            PostLoginRes kakaoLoinRes = authService.login(kakaoLoginReq);
////
////            br.close();
////            return result;
////        } catch (IOException exception) {
////            exception.printStackTrace();
////        }
////        return "4321";
//    }
//
//    @PostMapping("/check")
//    public JwtTokenDto check(HttpServletRequest request) throws GeneralSecurityException, IOException, JOSEException {
//
//        HttpTransport transport = Utils.getDefaultTransport();
//        JsonFactory jsonFactory = Utils.getDefaultJsonFactory();
//
//        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
//                .setAudience(Collections.singletonList("162441855133-gd4n562pio08v1jtjrcnlrvo7o35d0c7.apps.googleusercontent.com"))
//                .build();
//
//        String token = request.getHeader("Authorization");
//        GoogleIdToken idToken = verifier.verify(token);
//
//        if (idToken != null) {
//            GoogleIdToken.Payload payload = idToken.getPayload();
//
//            // Print user identifier
//            String userId = payload.getSubject();
//            System.out.println("User ID: " + userId);
//
//            // Get profile information from payload
//            String email = payload.getEmail();
//            boolean emailVerified = Boolean.valueOf(payload.getEmailVerified());
//            String name = (String) payload.get("name");
//            String pictureUrl = (String) payload.get("picture");
//            String givenName = (String) payload.get("given_name");
//
//            JwtTokenDto tokenDto = memberService.login(email, "1234");
//
//            return tokenDto;
//        } else {
//            System.out.println("Invalid ID token.");
//        }
//
//
//        return null;
//    }
//
//
//    @GetMapping("/please")
//    public String please() {
//        return "1234";
//    }
//}
