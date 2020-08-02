package com.kingsman.vo;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
@NoArgsConstructor
public class CartVO {
	private int cnum;
	@NonNull private String memail;
	@NonNull private int pserial;	
}
