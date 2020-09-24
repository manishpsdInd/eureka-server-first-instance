package com.example.demo.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private String USER = "USER";
	private String ADMIN = "ADMIN";

	@Value("${eureka.server.allowed.user.name}")
	private String userName;

	@Value("${eureka.server.allowed.user.password}")
	private String userPwd;

	@Value("${eureka.server.allowed.admin.name}")
	private String adminName;

	@Value("${eureka.server.allowed.admin.password}")
	private String adminPwd;

	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		auth.inMemoryAuthentication()
			//.withUser(userName).password(passwordEncoder().encode(userPwd)).roles(USER).and()
			.withUser(userName).password("{noop}"+userPwd).roles(USER).and()
			//.withUser(adminName).password(passwordEncoder().encode(adminPwd)).roles(ADMIN);
			.withUser(adminName).password("{noop}"+adminPwd).roles(ADMIN);
	}

	
	/*
	 * public PasswordEncoder passwordEncoder() { return new
	 * BCryptPasswordEncoder(); }
	 */
	 
	protected void configure(HttpSecurity http) throws Exception {

		http
			.logout().and().authorizeRequests().antMatchers("/logout").permitAll()
			.antMatchers("/**").hasRole("ADMIN").anyRequest().authenticated()
			.and().httpBasic()
			.and().csrf().disable();

	}
}