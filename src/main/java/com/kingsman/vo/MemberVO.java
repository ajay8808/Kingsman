package com.kingsman.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MemberVO {
	private String memail, mname, mphone, maddr;
	private int mcode; //1: 관리자 0: 멤버
	
}
