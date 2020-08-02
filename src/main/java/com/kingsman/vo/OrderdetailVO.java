package com.kingsman.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OrderdetailVO {
	private int pdserial;
	private int pdqty, pserial, onum;
}
