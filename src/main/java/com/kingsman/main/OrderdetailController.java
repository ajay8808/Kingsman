package com.kingsman.main;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.kingsman.service.OrderdetailService;
import com.kingsman.vo.OrderdetailVO;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController("orderdetailController")
public class OrderdetailController {
	@Autowired
	private OrderdetailService orderdetailService;
	
	@GetMapping("/orderdetails/{memail}")
	public Map display(@PathVariable("memail") String memail) {
		//log.info("memail = {}", memail);
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("memail", memail);
		this.orderdetailService.selectOrderdetail(map);
		List<OrderdetailVO> list = (List<OrderdetailVO>)map.get("orderdetailResult");
		OrderdetailVO orderdetail = list.get(0);
		map.remove("memail");
		map.remove("orderdetailResult");
		map.put("code", "success"); 
		map.put("orderdetailResult", orderdetail);
		return map;

	}
	
	@PostMapping("/orderdetails")
	public Map createOderDetail(@RequestBody OrderdetailVO detail) {
		log.info("전달받은 orderdetail : "+detail);
		this.orderdetailService.insertOrderdetail(detail);
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("code", "success");
		return map;
	}
	
	
} 
