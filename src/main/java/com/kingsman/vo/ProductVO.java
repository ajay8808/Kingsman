package com.kingsman.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProductVO {
	private int pserial;
	private String pname;
	private int pprice, psize;
	private String pcode, pimg;
}
