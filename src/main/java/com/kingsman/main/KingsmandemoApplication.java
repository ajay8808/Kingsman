package com.kingsman.main;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = "com.kingsman")
public class KingsmandemoApplication extends  SpringBootServletInitializer{
	

	@Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(KingsmandemoApplication.class);
    }


	public static void main(String[] args) {
		SpringApplication.run(KingsmandemoApplication.class, args);
	}

}
