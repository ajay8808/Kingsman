package com.kingsman.service;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.kingsman.dao.ProductDao;
import com.kingsman.vo.ProductVO;

@Service("productService")
public class ProductServiceImpl implements ProductService {

	@Autowired
	private ProductDao productDao;
	
	@Override
	public void selectProduct(Map map) {
		this.productDao.read(map);

	}
	@Override
	public void selectProductOne(Map map) {
		this.productDao.readOne(map);

	}

	@Override
	public void selectAllProducts(Map map) {
		this.productDao.readAll(map);

	}

	@Override
	public void updateProduct(ProductVO product) {
		this.productDao.update(product);

	}

}
