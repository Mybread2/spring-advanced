
package org.example.expert.config.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableScheduling
public class SchedulingConfig {
    // 스케줄링 활성화
    // TokenBlacklistService의 @Scheduled 메서드가 동작하도록 함
}