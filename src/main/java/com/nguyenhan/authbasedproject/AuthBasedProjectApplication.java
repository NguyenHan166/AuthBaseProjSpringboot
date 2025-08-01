package com.nguyenhan.authbasedproject;

import com.nguyenhan.authbasedproject.config.auth.BruteForceProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(BruteForceProperties.class)
public class AuthBasedProjectApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthBasedProjectApplication.class, args);
    }

}
