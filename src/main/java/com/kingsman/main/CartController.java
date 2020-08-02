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

import com.kingsman.service.CartService;
import com.kingsman.vo.CartVO;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController("cartController")
public class CartController {
	@Autowired
	private CartService cartService;
	
	@PostMapping("/cart")	
	public Map insertCart(@RequestBody CartVO cart) { //카트에 넣기
		this.cartService.insertCart(cart);
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("code", "success");
		return map;
	}
	
	@GetMapping("/cart/{memail}")
	public Map displayCart(@PathVariable String memail) { //readAll 카트담긴 상품 다 보여주기
		log.info("memail = {}", memail);
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("memail", memail);
		this.cartService.selectAllCarts(map);
		List<CartVO> list = (List<CartVO>)map.get("cartResults"); 
		map.put("code", "success");
		map.put("cartResults", list);		
		log.info(list.toString());		
		return map;
	}
	
	//@RequestMapping(value = "/Cart/{memail}", method=RequestMethod.DELETE)
	@DeleteMapping("/cart/{cnum}")
	public Map delete(@PathVariable("cnum") int cnum) {
		log.info("삭제할 카트의 번호 : {}", cnum );
		this.cartService.deleteCart(cnum);
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("code", "success");
		return map;	
	}
}


