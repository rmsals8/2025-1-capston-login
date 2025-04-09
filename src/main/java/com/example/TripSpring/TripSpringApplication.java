package com.example.TripSpring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.github.cdimascio.dotenv.Dotenv;

@SpringBootApplication
public class TripSpringApplication {
	public static void main(String[] args) {
		// .env 파일에서 환경 변수 로드
		Dotenv dotenv = Dotenv.load();
		dotenv.entries().forEach(entry -> System.setProperty(entry.getKey(), entry.getValue()));

		SpringApplication.run(TripSpringApplication.class, args);
	}
}