package com.cos.jwtex01.controller;

import com.cos.jwtex01.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * packageName    : com.cos.jwtex01.controller
 * fileName       : RefreshController
 * author         : 드림포원 디자이너2
 * date           : 2023-03-13
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-03-13        드림포원 디자이너2       최초 생성
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class RefreshController {


    private final JwtService jwtService;

    @PostMapping("/refresh")
    public ResponseEntity<Map> validateRefreshToken(@RequestBody HashMap<String, String> bodyJson, HttpServletResponse response) throws Exception {

        Map<String, Object> resultMap = new HashMap<>();

        log.info("refresh controller 실행");
        Map<String, String> map = jwtService.validateRefreshToken(bodyJson.get("refreshToken"), response);

        if(map.get("status").equals("402")){
            log.info("RefreshController - Refresh Token이 만료.");
//            RefreshApiResponseMessage refreshApiResponseMessage = new RefreshApiResponseMessage(map);
            resultMap.put("result", "N");
//            return new ResponseEntity<RefreshApiResponseMessage>(refreshApiResponseMessage, HttpStatus.UNAUTHORIZED);
            return new ResponseEntity<Map>(resultMap, HttpStatus.UNAUTHORIZED);

        }

        log.info("RefreshController - Refresh Token이 유효.");
        resultMap.put("result", "Y");
//        RefreshApiResponseMessage refreshApiResponseMessage = new RefreshApiResponseMessage(map);
        return new ResponseEntity<Map>(resultMap, HttpStatus.OK);

    }
}