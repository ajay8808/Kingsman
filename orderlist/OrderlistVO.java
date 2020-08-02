package com.kingsman.vo;

import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OrderlistVO {
	private int onum; 
	private Date odate;  
	private int ostatus, cmethod;
	private String memail;	
}
