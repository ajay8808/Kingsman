package com.kingsman.vo;

import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class MyOrderdetailVO {
	private String pname, pcode, pimg, pdserial, memail, mname, mphone, maddr;
	private int pserial, pprice, psize, pdqty, onum, mcode, ostatus, cmethod;
	private Date odate;
}

