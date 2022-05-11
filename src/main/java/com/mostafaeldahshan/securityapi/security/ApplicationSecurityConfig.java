package com.mostafaeldahshan.securityapi.security;

import com.mostafaeldahshan.securityapi.auth.ApplicationUserService;
import com.mostafaeldahshan.securityapi.jwt.JwtConfig;
import com.mostafaeldahshan.securityapi.jwt.JwtTokenVerifier;
import com.mostafaeldahshan.securityapi.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.mostafaeldahshan.securityapi.security.ApplicationUserRole.STUDENT;

@Configuration // indicates that the class has @Bean definition methods.
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //Linking the @PreAuthorize annotations
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    //Mandatory(By Spring Security) for encoding user passwords
    private final PasswordEncoder encoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;


    @Autowired // autowiring the password encoder to encode user passwords in this class.
    public ApplicationSecurityConfig(PasswordEncoder encoder, ApplicationUserService applicationUserService, SecretKey secretKey, JwtConfig jwtConfig) {
        this.encoder = encoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override // overridden function from WebSecurityConfigurerAdapter to allow configuration of http requests
    protected void configure(HttpSecurity http) throws Exception {
        http
                // Cross-Site Request Forgery disabling using token to secure the API.
                .csrf().disable()
                //CSRF configuration (no allowing cookies tokens to clients)
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()


                // making the api stateless(no need to know state of user as long as token match)
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig),JwtUsernameAndPasswordAuthenticationFilter.class)
                //for authorizing permitted requests.
                .authorizeRequests()
                //antMatches for specifying patterns(uri)/role_based/permission based authorities to current API.
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                // commented ant matchers for future revision(2nd way of permission based authorization)
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET, "management/api/**").hasAuthority(ADMINTRAINEE.name())
                .anyRequest()
                .authenticated();

//                .and()

                // ------------------------using BasicAuth Authorization.(No logout)-----------------------------------------
//                .httpBasic();

                // -------------------------FormBased Auth - not needed as JWT in action--------------------------------------
//                .formLogin()
//                    .loginPage("/login")
//                    .permitAll()
//                    .defaultSuccessUrl("/courses", true)
//                    .usernameParameter("username")
//                    .passwordParameter("password")
//                .and()
//                .rememberMe()
//                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21)) // increase duration of remember me
//                    .key("securityKey") // md5 hash key
//                    .rememberMeParameter("remember-me")
//                .and()
//                .logout()
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//                // when enabling csrf above line will be deleted as csrf uses POST method for logout
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID", "remember-me")
//                .logoutSuccessUrl("/login");
    }


    //----------------------------Using in memory user details builder--------------------------------------------------
//    @Override
//    @Bean //instantiating new Bean to Spring
//    protected UserDetailsService userDetailsService() { //overriding UserDetailsService func to build static users
//        UserDetails Student = User.builder()
//                .username("student")
//                .password(encoder.encode("student")) //using password encoder
////                .roles(STUDENT.name()) // granting student specific role_based authorities
//                .authorities(STUDENT.getGrantedAuthorities()) // granting student specific permission_based authorities
//                .build();
//
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password(encoder.encode("admin"))
////                .roles(ADMIN.name())
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails adminTrainee = User.builder()
//                .username("admintrainee")
//                .password(encoder.encode("trainee"))
////                .roles(ADMINTRAINEE.name())
//                .authorities(ADMINTRAINEE.getGrantedAuthorities())
//                .build();
//
//        return new InMemoryUserDetailsManager(// using InMemoryUserDetailsManager to test current built users
//                Student,
//                admin,
//                adminTrainee
//        );
//    }
    //------------------------------------------------------------------------------------------------------------------

    // wiring the custom-made Authentication provider to API
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    //providing the authenticationProvider with application user details
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(encoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
