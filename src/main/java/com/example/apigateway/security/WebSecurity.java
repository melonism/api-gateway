package com.example.apigateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {
    private Environment env;

    @Autowired
    public WebSecurity(Environment env ) {
        this.env = env;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        String baseUrl = env.getProperty("base.url.path");
        String loginUrl = env.getProperty("login.url.path");
        String usersUrl = env.getProperty("users.url.path");
        String h2ConsoleUrl = env.getProperty("h2console.url.path");
        String apiGatewayUrl = env.getProperty("api.zuul.actuator.url.path");
        String usersActuatorUrl = env.getProperty("api.users.actuator.url.path");

        http.csrf().disable();
        http.headers().frameOptions().disable();
        http.authorizeRequests()
            .antMatchers(usersActuatorUrl).permitAll()
            .antMatchers(apiGatewayUrl).permitAll()
            .antMatchers(baseUrl + h2ConsoleUrl).permitAll()
            .antMatchers(HttpMethod.POST, baseUrl + loginUrl).permitAll()
            .antMatchers(HttpMethod.POST, baseUrl + usersUrl).permitAll()
            .anyRequest().authenticated()
            .and()
            .addFilter(new AuthorizationFilter(authenticationManager(), env));
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    }
}
