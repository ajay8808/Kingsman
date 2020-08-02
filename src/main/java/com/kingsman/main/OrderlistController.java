package com.kingsman.main;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.kingsman.service.OrderlistService;
import com.kingsman.vo.CartVO;
import com.kingsman.vo.OrderlistVO;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController("orderlistController")
public class OrderlistController {
	@Autowired
	private OrderlistService orderlistService;
	
	@PostMapping("/orderlists")
	public Map orderinsert(@RequestBody OrderlistVO orderlist) {
		log.info("오더리스트 등록 : {}",orderlist);
		this.orderlistService.insertOrderlist(orderlist);
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("code", "success");
		return map;
	}
	
//	@GetMapping("/orderlists") 
//	public Map orderlists() {
//		Map<String, Object> map = new HashMap<String, Object>();
//		this.orderlistService.selectAllOrderlists(map);
//		List<OrderlistVO> list = (List<OrderlistVO>)map.get("orderlistResults");
//		list.forEach(orderlist -> log.info("" + orderlist));
//		map.put("code", "success");
//		return map;	
//	}
	
	@GetMapping("/orderlists/{memail}") 
	public Map orderlists(@PathVariable String memail) {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("memail", memail);
		this.orderlistService.selectAllOrderlists(map);
		List<OrderlistVO> list = (List<OrderlistVO>)map.get("orderlistResults");
		list.forEach(orderlist -> log.info("" + orderlist));
		map.put("code", "success");
		map.put("orderlistResults", list);
		return map;	
	}
	
	
	@GetMapping("/orderlist/{onum}")
	public Map display(@PathVariable("onum") int onum) {
		log.info("onum = {}", onum);
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("onum", onum);
		this.orderlistService.selectOrderlist(map);
		List<OrderlistVO> list = (List<OrderlistVO>)map.get("orderlistResult");
		OrderlistVO orderlist = list.get(0);
		map.remove("onum");
		map.remove("orderlistResult");
		map.put("code", "success");
		map.put("orderlistResult", orderlist);
		return map;
	}
	
	//@DeleteMapping("/orderlists/onum}")
	@DeleteMapping("/orderlists/onum}")
	public Map orderlistDelete(@PathVariable("onum") int onum) {
		log.info("삭제할 상품 : {}", onum);
		this.orderlistService.deleteOrderlist(onum);
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("code", "success");
		return map;
	}

	
}
