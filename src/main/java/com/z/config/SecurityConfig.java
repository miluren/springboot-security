package com.z.config;

import org.springframework.boot.web.server.WebServerException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

// 配置为Security的配置类
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * 首页所有人可以访问，功能页只有对应有权限的人才能访问
         * 请求授权的规则~
         */
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasAnyRole("vip1")
                .antMatchers("/level2/**").hasAnyRole("vip2")
                .antMatchers("/level3/**").hasAnyRole("vip3");

        /**
         *   没有权限默认会到登录页面，需要开启登录的页面
         *   login
         */
        http.formLogin()
         // 定制登陆页面
        .loginPage("/tologin")
        //  定制表单(前端form表单)的跳转页面(真正的登录页面)
        .loginProcessingUrl("/login")
        // 设置接收用户名,相当于 request.getParameter("user"),如果不设置，默认是username
        .usernameParameter("user");

        // 注销,开启了注销功能，跳到首页

        // 防止网站攻击： get ，post

        //  关闭  csrf(防止跨站攻击) ,注销失败可能存在的原因
        http.csrf().disable();
        http.logout().logoutSuccessUrl("/");

        //  开启记住我 功能
        http.rememberMe()
        //  配置了自己的登录界面，就需要设置新页面的 记住我
        .rememberMeParameter("remenber");

    }

    /**
     * 认证 , springboot 2.1.x  可以直接使用~
     * 密码编码： PasswordEncoder
     * 在Spring Security 5.0+ 新增了很多的加密方式~
     *
     * @param auth
     * @throws Exception
     */

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        // 这些数据正常应该从数据库中读
        // 设置权限
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("kuang").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");
    }
}
