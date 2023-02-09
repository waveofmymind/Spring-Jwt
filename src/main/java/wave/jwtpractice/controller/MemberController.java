package wave.jwtpractice.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import wave.jwtpractice.member.dto.MemberRequestDto;
import wave.jwtpractice.member.dto.MemberResponseDto;
import wave.jwtpractice.service.MemberService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/member")
public class MemberController {

    private final MemberService memberService;

    @GetMapping("/me")
    public ResponseEntity<MemberResponseDto> getMyMemberInfo() {
        MemberResponseDto myInfoBySecurity = memberService.getMyInfoBySecurity();
        System.out.println(myInfoBySecurity.getNickname());
        return ResponseEntity.ok((myInfoBySecurity));
        // return ResponseEntity.ok(memberService.getMyInfoBySecurity());
    }

    @PostMapping("/nickname")
    public ResponseEntity<MemberResponseDto> setMemberNickname(@RequestBody MemberRequestDto request) {
        return ResponseEntity.ok(memberService.changeMemberNickname(request.getEmail(), request.getNickname()));
    }


}