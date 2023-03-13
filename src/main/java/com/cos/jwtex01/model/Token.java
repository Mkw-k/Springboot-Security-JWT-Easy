package com.cos.jwtex01.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * packageName    : com.cos.jwtex01.model
 * fileName       : Token
 * author         : 드림포원 디자이너2
 * date           : 2023-03-13
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-03-13        드림포원 디자이너2       최초 생성
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Token {
    private String grantType;
    private String accessToken;
    private String refreshToken;
    private String key;

}