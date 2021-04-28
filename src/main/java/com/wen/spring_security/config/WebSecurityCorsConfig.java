package com.wen.spring_security.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * Spring Security配置
 */
@Configuration
@EnableWebSecurity  //开启Security
@EnableGlobalMethodSecurity(prePostEnabled = true)//开启Spring方法级安全
public class WebSecurityCorsConfig extends WebSecurityConfigurerAdapter {

    /**
     * 加密配置
     * @return
     */
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

 /*   *//**
     * 使用spring Security进行跨域配置
     * @return
     *//*
    @Bean
    public  CorsConfigurationSource corsConfigurationSource(){
        //创建跨域配置容器
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        //创建跨域配置pojo类
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowedOrigins(Arrays.asList("/*"));
        corsConfig.setMaxAge(3600L);
        corsConfig.setAllowedMethods(Arrays.asList("GET","POST","PUT","DELETE"));
        source.registerCorsConfiguration("/*",corsConfig);
        return source;
    }*/

    /**
     * 配置页面需要忽略的文件
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/img/**/*", "/**/*.css", "/**/*.js","/template/**","/plugins/**");
    }

    /**
     * 配置自定义登陆页面
     * @param http
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                .loginPage("/login.html")   //自定义登陆页面
                .loginProcessingUrl("/login.do")  //配置登陆请求的URL
                .defaultSuccessUrl("/pages/index.html")  //配置登陆成功的页面
                .and()
                .authorizeRequests().antMatchers("/pages/query.html").hasRole("ADMIN")
                .and()
                .authorizeRequests().antMatchers("/pages/**").authenticated()
                .and()
                .exceptionHandling().accessDeniedPage("/error.html") //配置登陆失败的界面
                .and()
                .csrf().disable(); //配置page文件夹下所有文件需要认证
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //  基于内存  定义认证用户的账号 、密码 、以及权限关键字
        auth.inMemoryAuthentication()
                .withUser("root").password(passwordEncoder().encode("root")).roles("ROOT")
                .and()
                .withUser("admin").password(passwordEncoder().encode("admin")).roles("ADMIN");
    }
}
