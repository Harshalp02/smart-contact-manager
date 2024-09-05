package com.smart.controller;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.Principal;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.smart.dao.ContactRepository;
import com.smart.dao.UserRepository;
import com.smart.entities.Contact;
import com.smart.entities.User;
import com.smart.helper.Message;

import jakarta.servlet.http.HttpSession;
import jakarta.websocket.Session;

@Controller
@RequestMapping("/user")
public class UserController {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private ContactRepository contactRepository;
	
	

	//method for adding common data to response
	@ModelAttribute
	public void addCommonData(Model model,Principal principal){
		String userName = principal.getName();
		System.out.println("USERNAME : "+userName);
		//get the user using username(Email)
		User user = userRepository.getUserByUserName(userName);
		System.out.println("USER : " + user);
		model.addAttribute("user", user);
	}

	//dashboard home
	@GetMapping("/index")
	public String dashboard(Model model,Principal principal) {
		model.addAttribute("title", "User Dashboard");
		return "normal/user_dashboard";
	}

	//open and form handler

	@GetMapping("/add-contact")
	public String openAddContactForm(Model model) {
		model.addAttribute("title", "Add Contact");
		model.addAttribute("contact", new Contact());
		return "normal/add_contact_form";
	}

	//processing add contact form

	@PostMapping("/process-contact")
	public String processContact(@ModelAttribute Contact contact,@RequestParam("profileImage") MultipartFile file ,Principal principal,HttpSession session) {

		try {
			String name = principal.getName();
			User user = this.userRepository.getUserByUserName(name);

			//processing and uploading file...
			
			if(file.isEmpty()) {
				System.out.println("File is empty..");
				contact.setImage("contact.jpg");
			}else {
				
				//upload the file to folder and update the name to contact
				contact.setImage(file.getOriginalFilename());
				
				File saveFile = new ClassPathResource("/static/img").getFile();
				
				Path path = Paths.get(saveFile.getAbsolutePath()+File.separator+file.getOriginalFilename());
				
				Files.copy(file.getInputStream(), path, StandardCopyOption.REPLACE_EXISTING);
				
				System.out.println("Image is uploaded..");
			}
			
			contact.setUser(user);

			user.getContacts().add(contact);
			
			this.userRepository.save(user);
			
			System.out.println("DATA :" + contact);
			System.out.println("Added to data base...");
			
			//message success
			
			session.setAttribute("message", new Message("Your contact is added !! add more..", "success"));

		}catch(Exception e) {
			System.out.println("ERROR :" + e.getMessage());
			e.printStackTrace();
			
			//message error
			session.setAttribute("message", new Message("Some thing went wrong !! try again..", "danger"));
		}
		
		return "normal/add_contact_form";
	}
	
	//show contacts handler
	//per page = 5
	//current page index = page[0]
	
	@GetMapping("/show-contacts/{page}")
	public String showContacts(@PathVariable("page") Integer page,Model model,Principal principal) {
		model.addAttribute("title", "Show User Contacts");
		
		//sending contacts list 
		String userName = principal.getName();
		User user = this.userRepository.getUserByUserName(userName);
		//pageable kade =>
	      //1. currentpage -> 5
	      //2. contact per page
		Pageable pageable = PageRequest.of(page, 4);
        Page<Contact> contacts = this.contactRepository.findContactsByUser(user.getId(),pageable);
        
        model.addAttribute("contacts", contacts);
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", contacts.getTotalPages());
		
		return "normal/show_contacts";
	}
	
	//showing particular contact details
	
	@GetMapping("/{cId}/contact")
	public String showContactDetails(@PathVariable("cId") Integer cId,Model model,Principal principal) {
		
		System.out.println("CID :" + cId);
		
		Optional<Contact> contactOptional = this.contactRepository.findById(cId);
		Contact contact = contactOptional.get();
		
		//Solving security bug
		
		String userName = principal.getName();
		User user = this.userRepository.getUserByUserName(userName);
		
		if(user.getId()==contact.getUser().getId()) {
			model.addAttribute("contact", contact);
			model.addAttribute("title", contact.getName());
		}
		
		return "normal/contact_detail";
	}
	
	//delete contact handler
	
	@GetMapping("/delete/{cId}")
	public String deleteContact(@PathVariable("cId") Integer cId,Model model,Principal principal,HttpSession session) {
		
//		Optional<Contact> contactOptional = this.contactRepository.findById(cId);
//		Contact contact = contactOptional.get();
		
		
		//modify line..
		Contact contact = this.contactRepository.findById(cId).get();
		
		String userName = principal.getName();
		User user = this.userRepository.getUserByUserName(userName);
		
		//check..
		if(user.getId()==contact.getUser().getId()) {
			contact.setUser(null);
			this.contactRepository.delete(contact);
		}
		
//		session.setAttribute("message", new Message("Contact deleted successfully..!!", "success"));
		
		return "redirect:/user/show-contacts/0";
	}
}
