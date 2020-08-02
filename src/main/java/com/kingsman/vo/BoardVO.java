package com.kingsman.vo;

import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class BoardVO {
	private int bnum;
	private String bcont;
	private Date bdate;
	private String memail;
	private int pserial;
}
