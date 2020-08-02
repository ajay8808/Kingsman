package com.kingsman.main;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kingsman.service.ProductService;
import com.kingsman.vo.ProductVO;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController("productController")
public class ProductController {
	
	public static String memail = null;
	
	@Autowired
	private ProductService productService;

	@GetMapping("/product")
	public Map sellectAll() {
		Map<String, Object> map = new HashMap<String, Object>();
		this.productService.selectAllProducts(map);
		
		List<ProductVO> list = (List<ProductVO>) map.get("productResults");
		//list.forEach(product -> log.info("" + product));
		map.put("code", "success");
		map.put("memail", ProductController.memail);
		//log.info("프로덕트컨트롤러의 email : "+ProductController.memail);
		return map;
	}

	@GetMapping("/product/{pcode}")
	public Map select(@PathVariable("pcode") String pcode, Model model) {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("pcode", pcode);
		this.productService.selectProduct(map);
		List<ProductVO> list = (List<ProductVO>) map.get("productResult");
		ProductVO product = null;
		if(list.size() >0)
			product = list.get(0);
		map.put("code", "success");
		log.info("프로덕트셀렉트의 이메일 : "+ProductController.memail);
		map.put("memail", ProductController.memail);
		map.put("product", product);
		model.addAttribute("memail", memail);
		return map;
	}
	
	@GetMapping("/productOne/{pserial}")
	public Map selectOne(@PathVariable("pserial") int pserial) {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("pserial", pserial);
		this.productService.selectProductOne(map);
		List<ProductVO> list = (List<ProductVO>) map.get("productResult");
		ProductVO product = list.get(0);
		map.put("code", "success");
		log.info("프로덕트셀렉트의 이메일 : "+ProductController.memail);
		map.put("memail", ProductController.memail);
		map.put("product", product);
		return map;
	}

	@PutMapping("/product/{pserial}")
	public Map update(@PathVariable int pserial, Model model) {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("pserial", pserial);
		this.productService.selectProduct(map);
		List<ProductVO> list = (List<ProductVO>) map.get("productResult");
		ProductVO product = list.get(0);
		map.put("productResult", product);
		log.info("수정할 pserial = " + pserial);
		return map;
	}
}
