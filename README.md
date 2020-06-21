# SpringSecurityJwtDemo
整合SpringSecurity+JWT的demo


附赠踩坑笔记:
# SpringSecurity自定义认证授权流程中的一个坑

今天在整合SpringSecurity+JWT的时候遇到一个巨坑: 角色授权一直无法使用


```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin")
    }
```
上面是我的配置,/admin路径下的api必须有admin的角色,官方demo中都是基于内存用户进行认证,写法是下面这样的:
```java
  	@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("asd").password("asd").roles("admin");
    }
```
这就等于创建了一个asd用户拥有admin角色,当用该用户登陆的时候便能访问该api接口




而你如果使用自定义的授权验证流程的话,那么你的用户应该是从数据库中查询出来的,包括角色,那你就需要创建一张用户表,生成一个对应的用户类,并且实现**_UserDetails_**接口_,_还要准备一张角色信息表_
```java
@Data
public class User implements Serializable , UserDetails {
    private String username;

    private String password;

    private static final long serialVersionUID = 1L;

    private List<SimpleGrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
    @Override
    public boolean isAccountNonExpired() {
        return false;
    }
    @Override
    public boolean isAccountNonLocked() {
        return false;
    }
    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }
    @Override
    public boolean isEnabled() {
        return false;
    }
}
```
一个简单的用户类


```java
@Data
public class Roles implements Serializable {
    private String username;

    private String role;

    private static final long serialVersionUID = 1L;
}
```
角色信息类






做好这个准备好我们就开始写过滤器来实现自己的认证流程
```java
public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter {
    public final static Algorithm algorithm = Algorithm.HMAC256("ASDFJKFnfsaf");
    public JwtLoginFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher(defaultFilterProcessesUrl));
        setAuthenticationManager(authenticationManager);
    }
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        /**
         * @author 6yi
         * @date 2020/6/21
         * @return
         * @Description 我们从登录参数中提取出用户名密码，然后调用 AuthenticationManager.authenticate() 方法去进行自动校验。
         **/
        String userName=request.getParameter("username");
        String password=request.getParameter("password");
        if(userName==null||password==null){
            response.setContentType("application/json;charset=utf-8");
            PrintWriter out = response.getWriter();
            out.write("请输入帐号和密码");
            out.flush();
            out.close();
        }
        return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(userName, password));
    } 
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        /**
         * @author 6yi
         * @date 2020/6/21
         * @return
         * @Description 校验成功回调方法
         **/
        //获取用户的权限
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        //拼接字符串
        StringBuffer as = new StringBuffer();
        for (GrantedAuthority authority : authorities) {
            as.append(authority.getAuthority())
                    .append(",");
        }
        //创建token
        String jwtToken = JWT.create()
                //配置用户的角色
                .withClaim("authorities", as.toString())
                .withSubject(authResult.getName())
                //过期时间
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .sign(algorithm);
        //返回token
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        out.write(new ObjectMapper().writeValueAsString(jwtToken));
        out.flush();
        out.close();
    }
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        /**
         * @author 6yi
         * @date 2020/6/21
         * @return
         * @Description 校验失败回调
         **/
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        out.write(failed.getMessage());
        out.flush();
        out.close();
    }
}
```
**AbstractAuthenticationProcessingFilter **验证请求入口,也就是登陆处理的地方
当我们设置好了登陆的url,就会来到该过滤器,先调用改过滤器的**attemptAuthentication**方法
我们从req中获取到用户名和密码,然后构造一个未验证的**_Authentication_**去**getAuthenticationManager().authenticate()**中进行验证
如果验证成功,则调用 **successfulAuthentication,**返回token给前端




将用户名和密码封装成**_Authentication_**后就要交给**AuthenticationProvider**去进行验证了,下面是一个实现的例子
```java
@Component
public class JwtUserProvider extends AbstractUserDetailsAuthenticationProvider {
    @Autowired
    UserService userService;
    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

    }
    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
            return userService.loadUserByUsername(username);
    }
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken userToken=(UsernamePasswordAuthenticationToken)authentication;
        UserDetails userDetails = retrieveUser(userToken.getPrincipal().toString(), userToken);
        /*
        *   这里可以追加各种验证,例如用户是否被Ban等等
        * */
        if(userDetails==null){
            throw new BadCredentialsException("NotFound this userName");
        }
        boolean isPassword= BCrypt.checkpw(userToken.getCredentials().toString(),userDetails.getPassword());
        if(isPassword){
            //返回一个新的UsernamePasswordAuthenticationToken
            return  createSuccessAuthentication(userDetails.getUsername(),authentication,userDetails);
        }else{
            throw new BadCredentialsException("Invalid username/password");
        }
    }
}

```
**Authentication**是贯穿整个SpringSecurity的认证信息,这里的是从上面filter传过来的,我们拿到之后就调用 **retrieveUser**方法去数据库中查询用户,查询完毕后再对比密码是否一直,如果一致的话再构建一个认证过的**Authentication**

通过UserDetailsService的loadUserByUsername方法从数据库中查询用户和角色信息,封装回去
```java
@Service
public class UserService implements UserDetailsService {
    @Autowired
    private UserDao userDao;
    @Autowired
    private RolesDao rolesDao;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //获取用户
        User user = userDao.selectByUserName(username);
        if(user!=null){
            //获取用户权限信息
            String[] rolesStr = rolesDao.selectByUserName(user.getUsername()).stream().map(h -> h.getRole()).toArray(String[]::new);
            try {
                user.setAuthorities(Arrays.stream(rolesStr).map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return user;
    }
}
```
最后成功就是调用Filter的**successfulAuthentication**方法了

然后就是调用API的时候怎么去验证.
我们也需要定制一个过滤器,调用API的时候进行过滤就可以了
```java
public class JwtFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain filterChain) throws ServletException, IOException {
        String jwtToken = req.getHeader("authorization");
        if(jwtToken==null){
            resp.setContentType("application/json;charset=utf-8");
            PrintWriter out = resp.getWriter();
            out.write("请登陆!");
            out.flush();
            out.close();
            return;
        }
        JWTVerifier verifier = JWT.require(JwtLoginFilter.algorithm).build();
        DecodedJWT decode;
        try {
            verifier.verify(jwtToken);
            decode = JWT.decode(jwtToken);
        }catch (Exception e){
            resp.setContentType("application/json;charset=UTF-8");
            resp.getWriter().write("token 失效");
            return;
        }
        //获取当前登录用户名
        String username = decode.getSubject();
        //获取角色权限
        List<GrantedAuthority> authorities = Arrays.stream(decode.getClaim("authorities").asString().split(",")).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, null, authorities);
        //将token放在threadloacl里
        token.setDetails(new WebAuthenticationDetails(req));
        SecurityContextHolder.getContext().setAuthentication(token);
        filterChain.doFilter(req,resp);
    }
}

```


先检查有没有携带token信息,再对token进行验证,成功的话就可以放行了

最后就是配置到配置文件里
```java
  @Override
    protected void configure(HttpSecurity http) throws Exception {
        //开启验证
        http.authorizeRequests()
            	//对admin进行角色授权
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/guest/**").hasRole("guest")
            	//登陆url不拦截
                .antMatchers(HttpMethod.POST, "/login").permitAll()
            	//其它所有的请求都拦截
                .anyRequest()
                .authenticated()
                .and()
            	//添加JWT登陆拦截器
                .addFilterAfter(new JwtLoginFilter("/login",authenticationManager()), UsernamePasswordAuthenticationFilter.class)
                //添加JWT验证拦截器
            	.addFilterAfter(new JwtFilter(),JwtLoginFilter.class)
            	//关闭csrf
                .csrf().disable();
    }
```


然后一顿操作猛如虎,发现授权一直不管用,就算获取到了token,授权了admin角色照样被拦截,百思不得其解,打开源码一看
```java
	public UserBuilder roles(String... roles) {
			List<GrantedAuthority> authorities = new ArrayList<>(
					roles.length);
			for (String role : roles) {
				Assert.isTrue(!role.startsWith("ROLE_"), () -> role
						+ " cannot start with ROLE_ (it is automatically added)");
				authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
			}
			return authorities(authorities);
		}
```


原来授权角色前面是要加"ROLE_"前缀的,我的妈呀,浪费半天时间,于是给数据的角色信息都加上了前缀,例如这样 "ROLE_admin",就能成功通过了.


