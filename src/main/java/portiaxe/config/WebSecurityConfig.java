package portiaxe.config;


import com.portiaxe.config.filter.JwtTokenAuthenticationFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // This method is used for override HttpSecurity of the web Application.
    // We can specify our authorization criteria inside this method.
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // starts authorizing configurations
        http.authorizeRequests()
                // ignore the "/" and "/index.html"
                .antMatchers("/",
                        "/login").permitAll()
                // authenticate all remaining URLS
                .anyRequest().authenticated().and()
                //.anyRequest().permitAll().and()
                // enabling the basic authentication
                .formLogin().disable()
                .httpBasic().disable()
                .addFilterBefore(new JwtTokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)

                //allow Cross Origin
                .cors().and()
                // disabling the CSRF - Cross Site Request Forgery
                .csrf().disable();

        // disable page caching
        http.headers().cacheControl();



    }
}
